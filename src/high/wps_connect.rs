//! Подключение к сети по WPS PIN.
//!
//! Слой связывает nl80211 и [`WpsEnrollee`]:
//!
//! 1. интерфейс переводится в managed-режим и подключается к `BSSID` с
//!    WPS-элементом `Request Type = Enrollee`;
//! 2. после ассоциации открывается `AF_PACKET`-сокет с ethertype `0x888e`;
//! 3. EAP-WSC обмен идёт в EAP-Expanded (vendor `00:37:2a`, тип `1`);
//! 4. из `M8` извлекаются `SSID`, `Network Key` и типы безопасности.
//!
//! Сохранение конфигурации и переподключение с полученным PSK — задача
//! вызывающего кода.

use std::time::{Duration, Instant};

use uu_linux_kernel_netlink::{AttrWriter, IfType};

use crate::high::nl80211_ext::{
    ATTR_AUTH_TYPE, ATTR_IE, ATTR_IFINDEX, ATTR_MAC, ATTR_SSID, ATTR_WIPHY_FREQ,
    AUTHTYPE_OPEN_SYSTEM, CMD_CONNECT,
};
use crate::high::scan::{Bss, DEFAULT_SCAN_WAIT};
use crate::high::wps_enrollee::{WpsCredentials, WpsEnrollee, message_type};
use crate::high::{Wlan, validate_unicast};
use crate::raw::eapol::{
    EAP_FAILURE, EAP_REQUEST, EAP_RESPONSE, EAP_TYPE_EXPANDED, EAP_TYPE_IDENTITY, EAPOL_TYPE_EAP,
    EAPOL_TYPE_START, ETHERTYPE_EAPOL, PAE_GROUP_ADDR, WPS_ATTR_REQUEST_TYPE, WPS_ATTR_VERSION,
    WPS_IDENTITY_ENROLLEE, WPS_MSG_M2, WPS_MSG_M2D, WPS_MSG_M4, WPS_MSG_M6, WPS_MSG_M8,
    WPS_REQUEST_TYPE_ENROLLEE, WPS_VENDOR_ID, WPS_VENDOR_TYPE, WPS_VERSION_1_0, WSC_FLAG_LF,
    WSC_FLAG_MF, WSC_FRAGMENT_SIZE, WSC_OP_DONE, WSC_OP_FRAG_ACK, WSC_OP_MSG, WSC_OP_NACK,
    WSC_OP_START, WpsTlvWriter, eap_identity, eapol, wps_eap,
};
use crate::raw::ie::IeList;
use crate::raw::mac::MacAddr;
use crate::raw::{Eap, EapExpanded, Eapol, PacketSocket};
use crate::{Error, Result};

/// Общий таймаут WPS-обмена по умолчанию.
pub const DEFAULT_WPS_TIMEOUT: Duration = Duration::from_secs(120);
/// Таймаут ожидания ассоциации с точкой доступа.
pub const DEFAULT_ASSOC_TIMEOUT: Duration = Duration::from_secs(20);

/// Таймаут одного чтения EAPOL-кадра.
const EAP_RECV_TIMEOUT: Duration = Duration::from_secs(3);
/// Интервал опроса статуса ассоциации.
const ASSOC_POLL: Duration = Duration::from_millis(250);
/// `NL80211_BSS_STATUS_ASSOCIATED`.
const BSS_STATUS_ASSOCIATED: u32 = 1;
/// Верхняя граница длины WSC-сообщения (как в hostap).
const WSC_MAX_MESSAGE: usize = 50_000;

impl Wlan {
    /// Подключается к сети по WPS PIN и возвращает учётные данные.
    ///
    /// # Errors
    ///
    /// Возвращает ошибку netlink, сокета или протокола, если интерфейс не
    /// удалось перевести в managed-режим, ассоциация не состоялась или
    /// регистратор отклонил PIN.
    pub fn wps_pin_psk(
        &mut self,
        ssid: &[u8],
        bssid: MacAddr,
        pin: &str,
    ) -> Result<WpsCredentials> {
        self.wps_pin_psk_with_timeout(ssid, bssid, pin, DEFAULT_WPS_TIMEOUT)
    }

    /// Подключается к сети по WPS PIN с явным таймаутом обмена.
    ///
    /// # Errors
    ///
    /// См. [`Wlan::wps_pin_psk`].
    pub fn wps_pin_psk_with_timeout(
        &mut self,
        ssid: &[u8],
        bssid: MacAddr,
        pin: &str,
        timeout: Duration,
    ) -> Result<WpsCredentials> {
        if ssid.is_empty() || ssid.len() > 32 {
            return Err(Error::Message("SSID must contain 1..=32 bytes".to_string()));
        }
        let bssid = validate_unicast(bssid)?;
        self.ensure_station()?;
        if self.disconnect().is_err() {
            trace!("disconnect before WPS failed");
        }

        let local = MacAddr::new(self.iface.mac);
        let enrollee = WpsEnrollee::new(local, pin)?;

        let frequency = self.scan_target(bssid)?.map(|bss| bss.frequency);
        self.connect_wps(ssid, bssid, frequency)?;
        self.wait_for_association(bssid, DEFAULT_ASSOC_TIMEOUT)?;

        let mut session = Session::new(&self.socket, local, bssid, enrollee);
        let credentials = session.run(timeout)?;
        trace!(
            ssid = %String::from_utf8_lossy(&credentials.ssid),
            "WPS credentials received"
        );
        Ok(credentials)
    }

    /// Переводит интерфейс в managed-режим и открывает EAPOL-сокет.
    fn ensure_station(&mut self) -> Result<()> {
        if self.iface.if_type != IfType::Station {
            self.nl.change_mode(&self.iface, IfType::Station, None)?;
            self.refresh()?;
        }
        uu_linux_kernel_netlink::set_if_up(&self.iface.name, true)?;
        self.socket = PacketSocket::open_ethertype(&self.iface.name, ETHERTYPE_EAPOL)?;
        Ok(())
    }

    /// Ищет `BSSID` в результатах сканирования.
    fn scan_target(&mut self, bssid: MacAddr) -> Result<Option<Bss>> {
        let mut found = None;
        self.scan_each_with(DEFAULT_SCAN_WAIT, |bss| {
            if found.is_none() && bss.bssid == bssid {
                found = Some(bss);
            }
        })?;
        Ok(found)
    }

    /// Отправляет `NL80211_CMD_CONNECT` с WPS-элементом ассоциации.
    fn connect_wps(&mut self, ssid: &[u8], bssid: MacAddr, frequency: Option<u32>) -> Result<()> {
        let mut wps = WpsTlvWriter::new();
        wps.u8(WPS_ATTR_VERSION, WPS_VERSION_1_0)?;
        wps.u8(WPS_ATTR_REQUEST_TYPE, WPS_REQUEST_TYPE_ENROLLEE)?;
        let mut ies = IeList::new();
        ies.wps(wps.as_bytes())?;

        let mut attrs = AttrWriter::new();
        attrs.u32(ATTR_IFINDEX, self.iface.index);
        attrs.bytes(ATTR_SSID, ssid);
        attrs.bytes(ATTR_MAC, &bssid.octets());
        attrs.bytes(ATTR_IE, ies.as_bytes());
        attrs.u32(ATTR_AUTH_TYPE, AUTHTYPE_OPEN_SYSTEM);
        if let Some(freq) = frequency {
            attrs.u32(ATTR_WIPHY_FREQ, freq);
        }

        let family = self.nl.family_id();
        self.nl.genl_mut().execute(family, CMD_CONNECT, 0, &attrs)?;
        trace!(len = ssid.len(), "WPS connect requested");
        Ok(())
    }

    /// Ждёт, пока `nl80211` сообщит об ассоциации с `bssid`.
    fn wait_for_association(&mut self, bssid: MacAddr, timeout: Duration) -> Result<()> {
        let deadline = deadline_after(timeout)?;
        loop {
            let mut associated = false;
            if self
                .scan_each(|bss| {
                    if bss.bssid == bssid && bss.status == Some(BSS_STATUS_ASSOCIATED) {
                        associated = true;
                    }
                })
                .is_err()
            {
                trace!("association status is not available yet");
            }
            if associated {
                trace!("associated with AP");
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(Error::Message(format!(
                    "timed out waiting for association with {bssid}"
                )));
            }
            std::thread::sleep(ASSOC_POLL);
        }
    }
}

/// Возвращает момент в будущем или ошибку при переполнении.
fn deadline_after(timeout: Duration) -> Result<Instant> {
    Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| Error::Message("timeout is too large".to_string()))
}

/// Состояние одного EAP-WSC обмена.
struct Session<'a> {
    socket: &'a PacketSocket,
    local: MacAddr,
    bssid: MacAddr,
    enrollee: WpsEnrollee,
    in_buf: Vec<u8>,
    in_op: Option<u8>,
    outgoing: Option<Outgoing>,
}

impl<'a> Session<'a> {
    const fn new(
        socket: &'a PacketSocket,
        local: MacAddr,
        bssid: MacAddr,
        enrollee: WpsEnrollee,
    ) -> Self {
        Self {
            socket,
            local,
            bssid,
            enrollee,
            in_buf: Vec::new(),
            in_op: None,
            outgoing: None,
        }
    }

    /// Проводит обмен до получения учётных данных.
    fn run(&mut self, timeout: Duration) -> Result<WpsCredentials> {
        self.socket.set_recv_timeout(Some(EAP_RECV_TIMEOUT))?;
        let deadline = deadline_after(timeout)?;
        self.send_eapol_start()?;
        loop {
            if Instant::now() >= deadline {
                return Err(Error::Message("WPS exchange timed out".to_string()));
            }
            let frame = match self.socket.recv() {
                Ok(frame) => frame,
                Err(Error::Io(error))
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    continue;
                }
                Err(error) => return Err(error),
            };
            if let Some(credentials) = self.handle_frame(&frame)? {
                return Ok(credentials);
            }
        }
    }

    /// Отправляет `EAPOL-Start` на групповой адрес `PAE`.
    fn send_eapol_start(&self) -> Result<()> {
        send_eapol_frame(self.socket, self.local, EAPOL_TYPE_START, &[])
    }

    /// Разбирает кадр и обрабатывает EAP-запрос.
    fn handle_frame(&mut self, frame: &[u8]) -> Result<Option<WpsCredentials>> {
        let Some((source, body)) = split_eapol_frame(frame) else {
            return Ok(None);
        };
        if source != self.bssid.octets() {
            return Ok(None);
        }
        let Some(eapol) = Eapol::parse(body) else {
            return Ok(None);
        };
        if eapol.packet_type != EAPOL_TYPE_EAP {
            return Ok(None);
        }
        match eapol.body.first().copied() {
            Some(EAP_REQUEST) => self.handle_request(eapol.body),
            Some(EAP_FAILURE) => Err(Error::Message("WPS registrar reported failure".to_string())),
            _ => Ok(None),
        }
    }

    /// Отвечает на `EAP-Request`.
    fn handle_request(&mut self, body: &[u8]) -> Result<Option<WpsCredentials>> {
        let Some(eap) = Eap::parse(body) else {
            return Ok(None);
        };
        match eap.packet_type {
            EAP_TYPE_IDENTITY => {
                let response = eap_identity(EAP_RESPONSE, eap.id, WPS_IDENTITY_ENROLLEE)?;
                self.send_eap(&response)?;
                Ok(None)
            }
            EAP_TYPE_EXPANDED => {
                let Some(expanded) = EapExpanded::parse(body) else {
                    return Ok(None);
                };
                if expanded.vendor_id != WPS_VENDOR_ID || expanded.vendor_type != WPS_VENDOR_TYPE {
                    return Ok(None);
                }
                self.handle_wsc(eap.id, expanded.data)
            }
            _ => Ok(None),
        }
    }

    /// Разбирает WSC-заголовок и собирает фрагменты.
    fn handle_wsc(&mut self, id: u8, data: &[u8]) -> Result<Option<WpsCredentials>> {
        let Some(&op_code) = data.first() else {
            return Ok(None);
        };
        let Some(&flags) = data.get(1) else {
            return Ok(None);
        };
        let position = if flags & WSC_FLAG_LF != 0 {
            let Some(length_bytes) = data.get(2..4) else {
                return Ok(None);
            };
            let total = usize::from(u16::from_be_bytes(
                <[u8; 2]>::try_from(length_bytes).map_err(|_| Error::Malformed)?,
            ));
            if total > WSC_MAX_MESSAGE {
                return Ok(None);
            }
            4
        } else {
            2
        };
        let Some(payload) = data.get(position..) else {
            return Ok(None);
        };

        if op_code == WSC_OP_FRAG_ACK {
            if let Some(outgoing) = self.outgoing.as_mut() {
                outgoing.send_next(self.socket, self.local, id)?;
                if outgoing.is_complete() {
                    self.outgoing = None;
                }
            }
            return Ok(None);
        }

        if self.in_op != Some(op_code) {
            self.in_buf.clear();
            self.in_op = Some(op_code);
        }
        self.in_buf.extend_from_slice(payload);
        if flags & WSC_FLAG_MF != 0 {
            return Ok(None);
        }
        let message = std::mem::take(&mut self.in_buf);
        self.in_op = None;
        self.handle_wsc_message(id, op_code, &message)
    }

    /// Обрабатывает op-code `WSC` и, если нужно, отвечает.
    fn handle_wsc_message(
        &mut self,
        id: u8,
        op_code: u8,
        message: &[u8],
    ) -> Result<Option<WpsCredentials>> {
        match op_code {
            WSC_OP_START => {
                let m1 = self.enrollee.m1()?;
                self.send_wsc(id, WSC_OP_MSG, &m1)?;
                Ok(None)
            }
            WSC_OP_MSG => self.handle_message(id, message),
            WSC_OP_NACK => Err(Error::Message(
                "WPS registrar rejected the exchange".to_string(),
            )),
            _ => Ok(None),
        }
    }

    /// Прогоняет `M2`–`M8` через state machine enrollee.
    fn handle_message(&mut self, id: u8, message: &[u8]) -> Result<Option<WpsCredentials>> {
        let Some(kind) = message_type(message) else {
            return Err(Error::Malformed);
        };
        match kind {
            WPS_MSG_M2 => {
                let m3 = self.enrollee.process_m2(message)?;
                self.send_wsc(id, WSC_OP_MSG, &m3)?;
                Ok(None)
            }
            WPS_MSG_M4 => {
                let m5 = self.enrollee.process_m4(message)?;
                self.send_wsc(id, WSC_OP_MSG, &m5)?;
                Ok(None)
            }
            WPS_MSG_M6 => {
                let m7 = self.enrollee.process_m6(message)?;
                self.send_wsc(id, WSC_OP_MSG, &m7)?;
                Ok(None)
            }
            WPS_MSG_M8 => {
                let credentials = self.enrollee.process_m8(message)?;
                let done = self.enrollee.wsc_done_message()?;
                self.send_wsc(id, WSC_OP_DONE, &done)?;
                Ok(Some(credentials))
            }
            WPS_MSG_M2D => Ok(None),
            _ => Err(Error::Message(format!(
                "unexpected WPS message type {kind:#04x}"
            ))),
        }
    }

    /// Отправляет `EAP-Response/Expanded` с WSC-сообщением.
    fn send_wsc(&mut self, id: u8, op_code: u8, payload: &[u8]) -> Result<()> {
        let mut outgoing = Outgoing::new(op_code, payload);
        outgoing.send_next(self.socket, self.local, id)?;
        if outgoing.is_complete() {
            self.outgoing = None;
        } else {
            self.outgoing = Some(outgoing);
        }
        Ok(())
    }

    /// Отправляет готовый `EAP`-пакет.
    fn send_eap(&self, eap: &[u8]) -> Result<()> {
        send_eapol_frame(self.socket, self.local, EAPOL_TYPE_EAP, eap)
    }
}

/// Исходящее WSC-сообщение, возможно разбитое на фрагменты.
struct Outgoing {
    op_code: u8,
    payload: Vec<u8>,
    offset: usize,
    fragment_size: usize,
}

impl Outgoing {
    fn new(op_code: u8, payload: &[u8]) -> Self {
        Self {
            op_code,
            payload: payload.to_vec(),
            offset: 0,
            fragment_size: WSC_FRAGMENT_SIZE,
        }
    }

    const fn is_complete(&self) -> bool {
        self.offset >= self.payload.len()
    }

    fn send_next(&mut self, socket: &PacketSocket, local: MacAddr, id: u8) -> Result<()> {
        let (body, next) = wsc_chunk(self.op_code, &self.payload, self.offset, self.fragment_size)?;
        let eap = wps_eap(EAP_RESPONSE, id, &body)?;
        send_eapol_frame(socket, local, EAPOL_TYPE_EAP, &eap)?;
        self.offset = next;
        Ok(())
    }
}

/// Формирует WSC-тело с учётом фрагментации.
///
/// Возвращает тело (`op-code`, `flags`, при необходимости длина) и смещение
/// следующего фрагмента.
fn wsc_chunk(
    op_code: u8,
    payload: &[u8],
    offset: usize,
    fragment_size: usize,
) -> Result<(Vec<u8>, usize)> {
    let remaining = payload.len().checked_sub(offset).ok_or(Error::Malformed)?;
    if remaining.saturating_add(2) <= fragment_size {
        let mut body = Vec::with_capacity(2 + remaining);
        body.push(op_code);
        body.push(0);
        body.extend_from_slice(payload.get(offset..).ok_or(Error::Malformed)?);
        return Ok((body, payload.len()));
    }

    let first = offset == 0;
    let (flags, chunk_len) = if first {
        (
            WSC_FLAG_MF | WSC_FLAG_LF,
            remaining.min(fragment_size.saturating_sub(4)),
        )
    } else {
        (WSC_FLAG_MF, remaining.min(fragment_size.saturating_sub(2)))
    };
    if chunk_len == 0 {
        return Err(Error::Message(
            "EAP-WSC fragment size is too small".to_string(),
        ));
    }
    let end = offset.checked_add(chunk_len).ok_or(Error::Malformed)?;
    let chunk = payload.get(offset..end).ok_or(Error::Malformed)?;

    let mut body = Vec::with_capacity(4 + chunk_len);
    body.push(op_code);
    body.push(flags);
    if flags & WSC_FLAG_LF != 0 {
        let total = u16::try_from(payload.len())
            .map_err(|_| Error::OutOfRange(i64::try_from(payload.len()).unwrap_or(i64::MAX)))?;
        body.extend_from_slice(&total.to_be_bytes());
    }
    body.extend_from_slice(chunk);
    Ok((body, end))
}

/// Делит Ethernet-кадр на MAC источника и тело `EAPOL`.
fn split_eapol_frame(frame: &[u8]) -> Option<([u8; 6], &[u8])> {
    let source = <[u8; 6]>::try_from(frame.get(6..12)?).ok()?;
    let ethertype = u16::from_be_bytes(<[u8; 2]>::try_from(frame.get(12..14)?).ok()?);
    if ethertype != ETHERTYPE_EAPOL {
        return None;
    }
    Some((source, frame.get(14..)?))
}

/// Собирает Ethernet + `EAPOL` кадр и отправляет его.
fn send_eapol_frame(
    socket: &PacketSocket,
    local: MacAddr,
    packet_type: u8,
    body: &[u8],
) -> Result<()> {
    let encoded = eapol(packet_type, body)?;
    let mut frame = Vec::with_capacity(14 + encoded.len());
    frame.extend_from_slice(&PAE_GROUP_ADDR);
    frame.extend_from_slice(&local.octets());
    frame.extend_from_slice(&ETHERTYPE_EAPOL.to_be_bytes());
    frame.extend_from_slice(&encoded);
    trace!(len = frame.len(), "EAPOL frame sent");
    socket.send(&frame)
}

#[cfg(test)]
mod tests {
    use super::{split_eapol_frame, wsc_chunk};
    use crate::raw::eapol::{
        ETHERTYPE_EAPOL, WSC_FLAG_LF, WSC_FLAG_MF, WSC_FRAGMENT_SIZE, WSC_OP_MSG,
    };

    #[test]
    fn splits_eapol_frame() {
        let mut frame = vec![0u8; 14];
        frame[6..12].copy_from_slice(&[1, 2, 3, 4, 5, 6]);
        frame[12..14].copy_from_slice(&ETHERTYPE_EAPOL.to_be_bytes());
        frame.extend_from_slice(&[0xaa, 0xbb]);
        let (source, body) = split_eapol_frame(&frame).unwrap();
        assert_eq!(source, [1, 2, 3, 4, 5, 6]);
        assert_eq!(body, &[0xaa, 0xbb]);
    }

    #[test]
    fn rejects_foreign_ethertype() {
        let frame = [0u8; 14];
        assert!(split_eapol_frame(&frame).is_none());
    }

    #[test]
    fn sends_small_message_without_fragments() {
        let payload = [0x11u8; 16];
        let (body, next) = wsc_chunk(WSC_OP_MSG, &payload, 0, WSC_FRAGMENT_SIZE).unwrap();
        assert_eq!(body[0], WSC_OP_MSG);
        assert_eq!(body[1], 0);
        assert_eq!(&body[2..], &payload);
        assert_eq!(next, payload.len());
    }

    #[test]
    fn fragments_large_message() {
        let payload = vec![0x22u8; WSC_FRAGMENT_SIZE * 2];
        let (first, next) = wsc_chunk(WSC_OP_MSG, &payload, 0, WSC_FRAGMENT_SIZE).unwrap();
        assert_eq!(first[0], WSC_OP_MSG);
        assert_eq!(first[1], WSC_FLAG_MF | WSC_FLAG_LF);
        let declared = u16::from_be_bytes([first[2], first[3]]);
        assert_eq!(usize::from(declared), payload.len());
        assert_eq!(first.len(), WSC_FRAGMENT_SIZE);

        let (second, next) = wsc_chunk(WSC_OP_MSG, &payload, next, WSC_FRAGMENT_SIZE).unwrap();
        assert_eq!(second[0], WSC_OP_MSG);
        assert_eq!(second[1], WSC_FLAG_MF);
        assert_eq!(second.len(), WSC_FRAGMENT_SIZE);

        let (last, end) = wsc_chunk(WSC_OP_MSG, &payload, next, WSC_FRAGMENT_SIZE).unwrap();
        assert_eq!(last[0], WSC_OP_MSG);
        assert_eq!(last[1], 0);
        assert_eq!(end, payload.len());
    }
}
