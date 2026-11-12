//! `AF_PACKET`-сокет для инъекции и приёма 802.11 кадров.
//!
//! Монитор-режим отдаёт кадры вместе с заголовком radiotap. Сокет не
//! буферизует больше одной дейтаграммы: память пропорциональна размеру
//! одного кадра.

use std::ffi::CString;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::time::Duration;

use crate::raw::radiotap::Radiotap;
use crate::{Error, Result};

/// Длина буфера для `MSG_PEEK`.
const PEEK_LEN: usize = 1;

fn socklen(len: usize) -> libc::socklen_t {
    libc::socklen_t::try_from(len).unwrap_or(libc::socklen_t::MAX)
}

/// Ethertype всех кадров (`ETH_P_ALL`).
const ETH_P_ALL_U16: u16 = 0x0003;

fn io_error() -> Error {
    let error = std::io::Error::last_os_error();
    match error.raw_os_error() {
        Some(libc::EPERM | libc::EACCES) => Error::PermissionDenied,
        _ => Error::Io(error),
    }
}

fn packaged_ifindex(name: &str) -> Result<i32> {
    let cname = CString::new(name).map_err(|_| Error::InterfaceNotFound(name.to_string()))?;
    // SAFETY: cname — валидная NUL-терминированная строка.
    let index = unsafe { libc::if_nametoindex(cname.as_ptr()) };
    if index == 0 {
        return Err(Error::InterfaceNotFound(name.to_string()));
    }
    i32::try_from(index).map_err(|_| Error::OutOfRange(i64::from(index)))
}

/// Сырой `AF_PACKET`/`SOCK_RAW`-сокет, привязанный к интерфейсу.
#[derive(Debug)]
pub struct PacketSocket {
    fd: OwnedFd,
    ifindex: i32,
    ifname: String,
    protocol: u16,
}

impl PacketSocket {
    /// Открывает сокет на интерфейсе `ifname` и принимает все кадры.
    ///
    /// # Errors
    ///
    /// Возвращает [`Error::InterfaceNotFound`] для неизвестного имени и
    /// [`Error::PermissionDenied`], если не хватает `CAP_NET_RAW`.
    pub fn open(ifname: &str) -> Result<Self> {
        Self::open_ethertype(ifname, ETH_P_ALL_U16)
    }

    /// Открывает сокет, ограниченный одним ethertype (например, `0x888e`).
    ///
    /// Ядро отфильтрует остальные кадры, поэтому пользовательский код
    /// разбирает только нужный протокол.
    ///
    /// # Errors
    ///
    /// Возвращает [`Error::InterfaceNotFound`] для неизвестного имени и
    /// [`Error::PermissionDenied`], если не хватает `CAP_NET_RAW`.
    pub fn open_ethertype(ifname: &str, ethertype: u16) -> Result<Self> {
        let ifindex = packaged_ifindex(ifname)?;
        let protocol = ethertype.to_be();
        // SAFETY: создаём сокет, дескриптор сразу переходит во владение OwnedFd.
        let raw_fd = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                i32::from(protocol),
            )
        };
        if raw_fd < 0 {
            return Err(io_error());
        }
        // SAFETY: raw_fd только что успешно создан и больше нигде не используется.
        let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
        let socket = Self {
            fd,
            ifindex,
            ifname: ifname.to_string(),
            protocol,
        };
        socket.bind()?;
        trace!(ifname, ifindex, protocol = ethertype, "packet socket ready");
        Ok(socket)
    }

    fn bind(&self) -> Result<()> {
        let mut address: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        address.sll_family = u16::try_from(libc::AF_PACKET)
            .map_err(|_| Error::OutOfRange(i64::from(libc::AF_PACKET)))?;
        address.sll_protocol = self.protocol;
        address.sll_ifindex = self.ifindex;
        // SAFETY: address инициализирован, длина соответствует типу.
        let rc = unsafe {
            libc::bind(
                self.fd.as_raw_fd(),
                (&raw const address).cast(),
                socklen(std::mem::size_of::<libc::sockaddr_ll>()),
            )
        };
        if rc < 0 {
            return Err(io_error());
        }
        Ok(())
    }

    /// Дескриптор сокета.
    #[must_use]
    pub fn as_raw_fd(&self) -> i32 {
        self.fd.as_raw_fd()
    }

    /// Индекс интерфейса.
    #[must_use]
    pub const fn ifindex(&self) -> i32 {
        self.ifindex
    }

    /// Имя интерфейса.
    #[must_use]
    pub fn ifname(&self) -> &str {
        &self.ifname
    }

    /// Отправляет готовый буфер без изменений.
    ///
    /// # Errors
    ///
    /// Возвращает [`Error::Io`] при ошибке `sendto(2)` или неполной отправке.
    pub fn send(&self, data: &[u8]) -> Result<()> {
        let mut address: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        address.sll_family = u16::try_from(libc::AF_PACKET)
            .map_err(|_| Error::OutOfRange(i64::from(libc::AF_PACKET)))?;
        address.sll_protocol = self.protocol;
        address.sll_ifindex = self.ifindex;

        trace!(ifname = %self.ifname, len = data.len(), "packet send");
        // SAFETY: указатели и длины соответствуют буферам.
        let rc = unsafe {
            libc::sendto(
                self.fd.as_raw_fd(),
                data.as_ptr().cast(),
                data.len(),
                0,
                (&raw const address).cast(),
                socklen(std::mem::size_of::<libc::sockaddr_ll>()),
            )
        };
        if rc < 0 {
            return Err(io_error());
        }
        if usize::try_from(rc).unwrap_or(0) != data.len() {
            return Err(Error::Message("short sendto".to_string()));
        }
        Ok(())
    }

    /// Отправляет radiotap-заголовок и следующий за ним 802.11 кадр.
    ///
    /// # Errors
    ///
    /// См. [`PacketSocket::send`].
    pub fn send_radiotap(&self, radiotap: &[u8], frame: &[u8]) -> Result<()> {
        let mut buffer = Vec::with_capacity(radiotap.len() + frame.len());
        buffer.extend_from_slice(radiotap);
        buffer.extend_from_slice(frame);
        self.send(&buffer)
    }

    /// Отправляет 802.11 кадр с минимальным radiotap-заголовком.
    ///
    /// # Errors
    ///
    /// См. [`PacketSocket::send`].
    pub fn send_frame(&self, frame: &[u8]) -> Result<()> {
        self.send_radiotap(&Radiotap::new().encode(), frame)
    }

    /// Читает одну дейтаграмму.
    ///
    /// # Errors
    ///
    /// Возвращает [`Error::Io`] при ошибке `recvfrom(2)`.
    pub fn recv(&self) -> Result<Vec<u8>> {
        let len = self.pending_len()?;
        let mut buffer = vec![0u8; len.max(PEEK_LEN)];
        // SAFETY: buffer выделен под len байт, указатели валидны.
        let rc = unsafe {
            libc::recvfrom(
                self.fd.as_raw_fd(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if rc < 0 {
            return Err(io_error());
        }
        let read = usize::try_from(rc).unwrap_or(0);
        trace!(ifname = %self.ifname, len = read, "packet recv");
        buffer.truncate(read);
        Ok(buffer)
    }

    fn pending_len(&self) -> Result<usize> {
        let mut peek = [0u8; PEEK_LEN];
        // SAFETY: буфер валиден; MSG_PEEK не забирает пакет из очереди.
        let rc = unsafe {
            libc::recvfrom(
                self.fd.as_raw_fd(),
                peek.as_mut_ptr().cast(),
                peek.len(),
                libc::MSG_PEEK | libc::MSG_TRUNC,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if rc < 0 {
            return Err(io_error());
        }
        Ok(usize::try_from(rc).unwrap_or(0))
    }

    /// Устанавливает таймаут чтения (`SO_RCVTIMEO`).
    ///
    /// # Errors
    ///
    /// Возвращает [`Error::Io`] при ошибке `setsockopt(2)`.
    pub fn set_recv_timeout(&self, timeout: Option<Duration>) -> Result<()> {
        let (secs, usecs) = timeout.map_or((0, 0), |duration| {
            (
                libc::time_t::try_from(duration.as_secs()).unwrap_or(libc::time_t::MAX),
                libc::suseconds_t::from(duration.subsec_micros()),
            )
        });
        let tv = libc::timeval {
            tv_sec: secs,
            tv_usec: usecs,
        };
        // SAFETY: tv живёт до конца вызова, длина соответствует типу.
        let rc = unsafe {
            libc::setsockopt(
                self.fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                (&raw const tv).cast(),
                socklen(std::mem::size_of::<libc::timeval>()),
            )
        };
        if rc < 0 {
            return Err(io_error());
        }
        Ok(())
    }

    /// Переключает блокирующий режим сокета.
    ///
    /// # Errors
    ///
    /// Возвращает [`Error::Io`] при ошибке `fcntl(2)`.
    pub fn set_nonblocking(&self, enabled: bool) -> Result<()> {
        // SAFETY: fcntl с корректным дескриптором.
        let flags = unsafe { libc::fcntl(self.fd.as_raw_fd(), libc::F_GETFL) };
        if flags < 0 {
            return Err(io_error());
        }
        let updated = if enabled {
            flags | libc::O_NONBLOCK
        } else {
            flags & !libc::O_NONBLOCK
        };
        // SAFETY: fcntl с корректным дескриптором и флагами.
        if unsafe { libc::fcntl(self.fd.as_raw_fd(), libc::F_SETFL, updated) } < 0 {
            return Err(io_error());
        }
        Ok(())
    }
}
