//! Высокоуровневый слой: интерфейс, канал, сканирование, подключение.
//!
//! Слой переиспользует [`crate::raw`] для инъекции и принимает решения
//! через `nl80211` из `uu-linux-kernel-netlink`.

mod nl80211_ext;

pub mod scan;
pub mod wps;
pub mod wps_connect;
pub mod wps_enrollee;

pub use scan::{Bss, DEFAULT_SCAN_WAIT, frequency_to_channel};
pub use wps::{WpsIe, app_pin_candidates, pin_candidates};
pub use wps_connect::{DEFAULT_ASSOC_TIMEOUT, DEFAULT_WPS_TIMEOUT};
pub use wps_enrollee::{WpsCredentials, WpsEnrollee};

use uu_linux_kernel_netlink::{AttrWriter, IfType, Nl80211, WifiInterface};

use crate::raw::{MacAddr, PacketSocket, Radiotap};
use crate::{Error, Result};

use self::nl80211_ext::{
    ATTR_AUTH_TYPE, ATTR_IFINDEX, ATTR_SSID, AUTHTYPE_OPEN_SYSTEM, CMD_CONNECT, CMD_DISCONNECT,
};

/// Wi-Fi-интерфейс с доступом к `nl80211` и `AF_PACKET`.
#[derive(Debug)]
pub struct Wlan {
    nl: Nl80211,
    iface: WifiInterface,
    socket: PacketSocket,
}

impl Wlan {
    /// Открывает `nl80211` и `AF_PACKET`-сокет для интерфейса.
    ///
    /// # Errors
    ///
    /// Возвращает [`Error::InterfaceNotFound`], если интерфейс отсутствует,
    /// или ошибку netlink/сокета.
    pub fn open(ifname: &str) -> Result<Self> {
        let mut nl = Nl80211::open()?;
        let iface = nl.interface_by_name(ifname)?;
        let socket = PacketSocket::open(ifname)?;
        trace!(ifname, ifindex = iface.index, "wlan opened");
        Ok(Self { nl, iface, socket })
    }

    /// Ссылка на `nl80211`.
    #[must_use]
    pub const fn nl(&self) -> &Nl80211 {
        &self.nl
    }

    /// Изменяемая ссылка на `nl80211`.
    #[must_use]
    pub const fn nl_mut(&mut self) -> &mut Nl80211 {
        &mut self.nl
    }

    /// Описание интерфейса на момент последнего обновления.
    #[must_use]
    pub const fn iface(&self) -> &WifiInterface {
        &self.iface
    }

    /// `AF_PACKET`-сокет.
    #[must_use]
    pub const fn socket(&self) -> &PacketSocket {
        &self.socket
    }

    /// Имя интерфейса.
    #[must_use]
    pub fn ifname(&self) -> &str {
        &self.iface.name
    }

    /// Перечитывает описание интерфейса из `nl80211`.
    ///
    /// # Errors
    ///
    /// Возвращает ошибку dump-запроса интерфейсов.
    pub fn refresh(&mut self) -> Result<()> {
        let name = self.iface.name.clone();
        self.iface = self.nl.interface_by_name(&name)?;
        Ok(())
    }

    /// Переводит интерфейс в monitor-режим.
    ///
    /// # Errors
    ///
    /// Возвращает ошибку смены режима или обновления описания.
    pub fn set_monitor(&mut self) -> Result<()> {
        self.nl.change_mode(&self.iface, IfType::Monitor, None)?;
        self.refresh()
    }

    /// Переводит интерфейс в managed-режим.
    ///
    /// # Errors
    ///
    /// Возвращает ошибку смены режима или обновления описания.
    pub fn set_managed(&mut self) -> Result<()> {
        self.nl.change_mode(&self.iface, IfType::Station, None)?;
        self.refresh()
    }

    /// Переключает канал.
    ///
    /// # Errors
    ///
    /// Возвращает ошибку netlink или [`Error::Netlink`] для неизвестного
    /// канала.
    pub fn set_channel(&mut self, channel: u8) -> Result<()> {
        self.nl.set_channel(self.iface.index, channel)?;
        trace!(channel, "channel set");
        Ok(())
    }

    /// Переключает интерфейс на частоту в `МГц`.
    ///
    /// # Errors
    ///
    /// Возвращает ошибку netlink.
    pub fn set_frequency(&mut self, frequency: u32) -> Result<()> {
        self.nl.set_frequency(self.iface.index, frequency)?;
        Ok(())
    }

    /// Отправляет 802.11 кадр с минимальным radiotap-заголовком.
    ///
    /// # Errors
    ///
    /// См. [`PacketSocket::send_frame`].
    pub fn send_frame(&self, frame: &[u8]) -> Result<()> {
        self.socket.send_frame(frame)
    }

    /// Отправляет кадр с заданным radiotap-заголовком.
    ///
    /// # Errors
    ///
    /// См. [`PacketSocket::send_radiotap`].
    pub fn send_radiotap(&self, radiotap: &Radiotap, frame: &[u8]) -> Result<()> {
        self.socket.send_radiotap(&radiotap.encode(), frame)
    }

    /// Читает один кадр из сокета.
    ///
    /// # Errors
    ///
    /// См. [`PacketSocket::recv`].
    pub fn recv(&self) -> Result<Vec<u8>> {
        self.socket.recv()
    }

    /// Подключается к открытой сети.
    ///
    /// Для WPA/WPA2 нужен userspace-supplicant: `nl80211` сам по себе
    /// выполняет только открытую аутентификацию.
    ///
    /// # Errors
    ///
    /// Возвращает ошибку netlink, если драйвер отклонил подключение.
    pub fn connect_open(&mut self, ssid: &[u8]) -> Result<()> {
        if ssid.is_empty() {
            return Err(Error::Message("SSID must not be empty".to_string()));
        }
        let mut attrs = AttrWriter::new();
        attrs.u32(ATTR_IFINDEX, self.iface.index);
        attrs.bytes(ATTR_SSID, ssid);
        attrs.u32(ATTR_AUTH_TYPE, AUTHTYPE_OPEN_SYSTEM);

        let family = self.nl.family_id();
        self.nl.genl_mut().execute(family, CMD_CONNECT, 0, &attrs)?;
        trace!(len = ssid.len(), "connect requested");
        Ok(())
    }

    /// Отключается от текущей сети.
    ///
    /// # Errors
    ///
    /// Возвращает ошибку netlink.
    pub fn disconnect(&mut self) -> Result<()> {
        let mut attrs = AttrWriter::new();
        attrs.u32(ATTR_IFINDEX, self.iface.index);
        let family = self.nl.family_id();
        self.nl
            .genl_mut()
            .execute(family, CMD_DISCONNECT, 0, &attrs)?;
        trace!("disconnect requested");
        Ok(())
    }
}

/// Проверяет, что MAC-адрес не является широковещательным.
///
/// # Errors
///
/// Возвращает [`Error::Mac`] для широковещательного адреса.
pub fn validate_unicast(address: MacAddr) -> Result<MacAddr> {
    if address.is_multicast() {
        return Err(Error::Mac(format!("{address} is not unicast")));
    }
    Ok(address)
}
