//! Кадры 802.11: управляющие и данные.
//!
//! Заголовок кадра собирается вручную, без промежуточных структур: это
//! позволяет инжектить кадры на устройствах с малым объёмом памяти.

use crate::raw::ie::IeList;
use crate::raw::mac::MacAddr;
use crate::{Error, Result};

/// Тип кадра `Management`.
pub const FC_TYPE_MANAGEMENT: u8 = 0;
/// Тип кадра `Control`.
pub const FC_TYPE_CONTROL: u8 = 1;
/// Тип кадра `Data`.
pub const FC_TYPE_DATA: u8 = 2;
/// Тип кадра `Extension`.
pub const FC_TYPE_EXTENSION: u8 = 3;

/// Флаг `To DS`.
pub const FC_FLAG_TO_DS: u16 = 0x0100;
/// Флаг `From DS`.
pub const FC_FLAG_FROM_DS: u16 = 0x0200;
/// Флаг `More Fragments`.
pub const FC_FLAG_MORE_FRAG: u16 = 0x0400;
/// Флаг `Retry`.
pub const FC_FLAG_RETRY: u16 = 0x0800;
/// Флаг `Power Management`.
pub const FC_FLAG_POWER_MGMT: u16 = 0x1000;
/// Флаг `More Data`.
pub const FC_FLAG_MORE_DATA: u16 = 0x2000;
/// Флаг `Protected Frame`.
pub const FC_FLAG_PROTECTED: u16 = 0x4000;
/// Флаг `Order`.
pub const FC_FLAG_ORDER: u16 = 0x8000;

/// Подтип `Association Request`.
pub const MGMT_ASSOC_REQUEST: u8 = 0;
/// Подтип `Association Response`.
pub const MGMT_ASSOC_RESPONSE: u8 = 1;
/// Подтип `Reassociation Request`.
pub const MGMT_REASSOC_REQUEST: u8 = 2;
/// Подтип `Reassociation Response`.
pub const MGMT_REASSOC_RESPONSE: u8 = 3;
/// Подтип `Probe Request`.
pub const MGMT_PROBE_REQUEST: u8 = 4;
/// Подтип `Probe Response`.
pub const MGMT_PROBE_RESPONSE: u8 = 5;
/// Подтип `Beacon`.
pub const MGMT_BEACON: u8 = 8;
/// Подтип `ATIM`.
pub const MGMT_ATIM: u8 = 9;
/// Подтип `Disassociation`.
pub const MGMT_DISASSOC: u8 = 10;
/// Подтип `Authentication`.
pub const MGMT_AUTH: u8 = 11;
/// Подтип `Deauthentication`.
pub const MGMT_DEAUTH: u8 = 12;
/// Подтип `Action`.
pub const MGMT_ACTION: u8 = 13;
/// Подтип `Action No Ack`.
pub const MGMT_ACTION_NO_ACK: u8 = 14;

/// Подтип `Data`.
pub const DATA_SUBTYPE_DATA: u8 = 0;
/// Подтип `Null`.
pub const DATA_SUBTYPE_NULL: u8 = 4;
/// Подтип `QoS Data`.
pub const DATA_SUBTYPE_QOS_DATA: u8 = 8;

/// `LLC/SNAP`-заголовок для `EAPOL` (`AA AA 03 00 00 00 88 8E`).
pub const LLC_SNAP_EAPOL: [u8; 8] = [0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e];

/// Причина деаутентификации: `Class 3 frame received from nonassociated station`.
pub const REASON_CLASS3_FRAME: u16 = 7;

/// Поле `Frame Control`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FrameControl(u16);

impl FrameControl {
    /// Собирает `Frame Control` из типа, подтипа и флагов.
    #[must_use]
    pub const fn new(frame_type: u8, subtype: u8, flags: u16) -> Self {
        let version = 0u16;
        let type_bits = u16::from_le_bytes([frame_type, 0]).wrapping_shl(2);
        let subtype_bits = u16::from_le_bytes([subtype, 0]).wrapping_shl(4);
        Self(version | type_bits | subtype_bits | flags)
    }

    /// Сырое значение в порядке little-endian.
    #[must_use]
    pub const fn raw(self) -> u16 {
        self.0
    }

    /// Тип кадра.
    #[must_use]
    pub const fn frame_type(self) -> u8 {
        ((self.0 >> 2) & 0x3).to_le_bytes()[0]
    }

    /// Подтип кадра.
    #[must_use]
    pub const fn subtype(self) -> u8 {
        ((self.0 >> 4) & 0x0f).to_le_bytes()[0]
    }

    /// Флаги кадра.
    #[must_use]
    pub const fn flags(self) -> u16 {
        self.0 & 0xff00
    }
}

/// Общий заголовок управляющего кадра (24 байта).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MgmtHeader {
    /// Подтип (`MGMT_*`).
    pub subtype: u8,
    /// Флаги `FC_FLAG_*`.
    pub flags: u16,
    /// Поле `Duration`.
    pub duration: u16,
    /// Адрес получателя (`Address 1`).
    pub destination: MacAddr,
    /// Адрес отправителя (`Address 2`).
    pub source: MacAddr,
    /// `BSSID` (`Address 3`).
    pub bssid: MacAddr,
    /// Номер последовательности (12 бит).
    pub sequence: u16,
}

impl MgmtHeader {
    /// Длина заголовка в байтах.
    pub const LEN: usize = 24;

    /// Создаёт заголовок управляющего кадра с нулевым `Duration` и `Sequence`.
    #[must_use]
    pub const fn new(subtype: u8, destination: MacAddr, source: MacAddr, bssid: MacAddr) -> Self {
        Self {
            subtype,
            flags: 0,
            duration: 0,
            destination,
            source,
            bssid,
            sequence: 0,
        }
    }

    /// Задаёт флаги.
    #[must_use]
    pub const fn with_flags(mut self, flags: u16) -> Self {
        self.flags = flags;
        self
    }

    /// Задаёт `Duration`.
    #[must_use]
    pub const fn with_duration(mut self, duration: u16) -> Self {
        self.duration = duration;
        self
    }

    /// Задаёт номер последовательности.
    #[must_use]
    pub const fn with_sequence(mut self, sequence: u16) -> Self {
        self.sequence = sequence;
        self
    }

    /// Собирает заголовок и тело в готовый кадр.
    #[must_use]
    pub fn encode(&self, body: &[u8]) -> Vec<u8> {
        let control = FrameControl::new(FC_TYPE_MANAGEMENT, self.subtype, self.flags);
        let mut out = Vec::with_capacity(Self::LEN + body.len());
        out.extend_from_slice(&control.raw().to_le_bytes());
        out.extend_from_slice(&self.duration.to_le_bytes());
        out.extend_from_slice(self.destination.as_bytes());
        out.extend_from_slice(self.source.as_bytes());
        out.extend_from_slice(self.bssid.as_bytes());
        out.extend_from_slice(&self.sequence.wrapping_shl(4).to_le_bytes());
        out.extend_from_slice(body);
        out
    }
}

/// Собирает кадр деаутентификации.
#[must_use]
pub fn deauthenticate(bssid: MacAddr, station: MacAddr, reason: u16) -> Vec<u8> {
    let header = MgmtHeader::new(MGMT_DEAUTH, station, bssid, bssid);
    header.encode(&reason.to_le_bytes())
}

/// Собирает кадр диссоциации.
#[must_use]
pub fn disassociate(bssid: MacAddr, station: MacAddr, reason: u16) -> Vec<u8> {
    let header = MgmtHeader::new(MGMT_DISASSOC, station, bssid, bssid);
    header.encode(&reason.to_le_bytes())
}

/// Собирает `Probe Request`.
///
/// # Errors
///
/// Возвращает ошибку, если SSID длиннее `255` байт.
pub fn probe_request(source: MacAddr, ssid: Option<&[u8]>) -> Result<Vec<u8>> {
    let mut elements = IeList::new();
    elements.ssid(ssid.unwrap_or(&[]))?;
    elements.rates(DEFAULT_RATES)?;

    let header = MgmtHeader::new(
        MGMT_PROBE_REQUEST,
        MacAddr::BROADCAST,
        source,
        MacAddr::BROADCAST,
    );
    Ok(header.encode(elements.as_bytes()))
}

/// Собирает `Beacon`.
///
/// # Errors
///
/// Возвращает ошибку, если SSID длиннее `255` байт.
pub fn beacon(bssid: MacAddr, ssid: &[u8], channel: u8, interval: u16) -> Result<Vec<u8>> {
    beacon_like(MGMT_BEACON, bssid, ssid, channel, interval)
}

/// Собирает `Probe Response`.
///
/// # Errors
///
/// Возвращает ошибку, если SSID длиннее `255` байт.
pub fn probe_response(bssid: MacAddr, ssid: &[u8], channel: u8, interval: u16) -> Result<Vec<u8>> {
    beacon_like(MGMT_PROBE_RESPONSE, bssid, ssid, channel, interval)
}

fn beacon_like(
    subtype: u8,
    bssid: MacAddr,
    ssid: &[u8],
    channel: u8,
    interval: u16,
) -> Result<Vec<u8>> {
    let mut elements = IeList::new();
    elements.ssid(ssid)?;
    elements.rates(DEFAULT_RATES)?;
    elements.ds_parameter(channel)?;

    let mut body = Vec::with_capacity(12 + elements.as_bytes().len());
    body.extend_from_slice(&0u64.to_le_bytes());
    body.extend_from_slice(&interval.to_le_bytes());
    body.extend_from_slice(&CAPABILITY_ESS.to_le_bytes());
    body.extend_from_slice(elements.as_bytes());

    let header = MgmtHeader::new(subtype, MacAddr::BROADCAST, bssid, bssid);
    Ok(header.encode(&body))
}

/// Собирает кадр аутентификации с открытой системой.
#[must_use]
pub fn auth_open(bssid: MacAddr, station: MacAddr) -> Vec<u8> {
    let body = [
        0u8, 0, // Open System
        1, 0, // Authentication sequence 1
        0, 0, // Status: success
    ];
    let header = MgmtHeader::new(MGMT_AUTH, bssid, station, bssid);
    header.encode(&body)
}

/// Собирает `Action`-кадр.
#[must_use]
pub fn action(
    destination: MacAddr,
    source: MacAddr,
    bssid: MacAddr,
    category: u8,
    payload: &[u8],
) -> Vec<u8> {
    let mut body = Vec::with_capacity(1 + payload.len());
    body.push(category);
    body.extend_from_slice(payload);
    let header = MgmtHeader::new(MGMT_ACTION, destination, source, bssid);
    header.encode(&body)
}

/// Собирает кадр данных с произвольным `LLC/SNAP`-payload.
#[must_use]
pub fn data_frame(
    subtype: u8,
    destination: MacAddr,
    source: MacAddr,
    bssid: MacAddr,
    flags: u16,
    payload: &[u8],
) -> Vec<u8> {
    let control = FrameControl::new(FC_TYPE_DATA, subtype, flags);
    let mut out = Vec::with_capacity(24 + payload.len());
    out.extend_from_slice(&control.raw().to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(destination.as_bytes());
    out.extend_from_slice(source.as_bytes());
    out.extend_from_slice(bssid.as_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(payload);
    out
}

/// Собирает `EAPOL`-кадр данных с `LLC/SNAP`.
#[must_use]
pub fn eapol_data(
    destination: MacAddr,
    source: MacAddr,
    bssid: MacAddr,
    flags: u16,
    eapol: &[u8],
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(LLC_SNAP_EAPOL.len() + eapol.len());
    payload.extend_from_slice(&LLC_SNAP_EAPOL);
    payload.extend_from_slice(eapol);
    data_frame(
        DATA_SUBTYPE_DATA,
        destination,
        source,
        bssid,
        flags,
        &payload,
    )
}

/// `EAPOL`-кадр от точки доступа к станции (`From DS`).
#[must_use]
pub fn eapol_from_ap(station: MacAddr, ap: MacAddr, eapol: &[u8]) -> Vec<u8> {
    eapol_data(station, ap, ap, FC_FLAG_FROM_DS, eapol)
}

/// `EAPOL`-кадр от станции к точке доступа (`To DS`).
#[must_use]
pub fn eapol_to_ap(station: MacAddr, ap: MacAddr, eapol: &[u8]) -> Vec<u8> {
    eapol_data(ap, station, ap, FC_FLAG_TO_DS, eapol)
}

/// Разбирает `Frame Control` из начала кадра.
#[must_use]
pub fn parse_frame_control(frame: &[u8]) -> Option<FrameControl> {
    let raw = frame.get(0..2)?;
    Some(FrameControl(u16::from_le_bytes(raw.try_into().ok()?)))
}

/// Возвращает `true`, если кадр является `EAPOL`-кадром данных.
#[must_use]
pub fn is_eapol(frame: &[u8]) -> bool {
    let Some(control) = parse_frame_control(frame) else {
        return false;
    };
    if control.frame_type() != FC_TYPE_DATA {
        return false;
    }
    let Some(payload) = frame.get(MgmtHeader::LEN..) else {
        return false;
    };
    payload.starts_with(&LLC_SNAP_EAPOL)
}

const DEFAULT_RATES: &[u8] = &[0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24];
const CAPABILITY_ESS: u16 = 0x0001;

/// Возвращает ошибку, если кадр короче заголовка.
///
/// # Errors
///
/// Возвращает [`Error::Malformed`], если данных недостаточно.
pub const fn require_len(data: &[u8], len: usize) -> Result<()> {
    if data.len() < len {
        return Err(Error::Malformed);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        FC_FLAG_FROM_DS, FC_FLAG_TO_DS, FC_TYPE_DATA, FC_TYPE_MANAGEMENT, FrameControl,
        LLC_SNAP_EAPOL, MGMT_BEACON, MGMT_DEAUTH, MacAddr, MgmtHeader, beacon, deauthenticate,
        eapol_data, eapol_from_ap, is_eapol, parse_frame_control, probe_request,
    };

    const AP: MacAddr = MacAddr::new([0x02, 0, 0, 0, 0, 1]);
    const STA: MacAddr = MacAddr::new([0x02, 0, 0, 0, 0, 2]);

    #[test]
    fn encodes_frame_control() {
        let control = FrameControl::new(FC_TYPE_MANAGEMENT, MGMT_DEAUTH, 0);
        assert_eq!(control.raw(), 0x00c0);
        assert_eq!(control.frame_type(), FC_TYPE_MANAGEMENT);
        assert_eq!(control.subtype(), MGMT_DEAUTH);

        let data = FrameControl::new(FC_TYPE_DATA, 0, FC_FLAG_TO_DS | FC_FLAG_FROM_DS);
        assert_eq!(data.flags(), FC_FLAG_TO_DS | FC_FLAG_FROM_DS);
    }

    #[test]
    fn builds_deauth_frame() {
        let frame = deauthenticate(AP, STA, 7);
        assert_eq!(frame.len(), 26);
        let control = parse_frame_control(&frame).unwrap();
        assert_eq!(control.frame_type(), FC_TYPE_MANAGEMENT);
        assert_eq!(control.subtype(), MGMT_DEAUTH);
        assert_eq!(MacAddr::from_bytes(&frame[4..10]), Some(STA));
        assert_eq!(MacAddr::from_bytes(&frame[10..16]), Some(AP));
        assert_eq!(MacAddr::from_bytes(&frame[16..22]), Some(AP));
        assert_eq!(&frame[24..26], &7u16.to_le_bytes());
    }

    #[test]
    fn builds_probe_request_with_wildcard_ssid() {
        let frame = probe_request(STA, None).unwrap();
        let header = MgmtHeader::new(
            super::MGMT_PROBE_REQUEST,
            MacAddr::BROADCAST,
            STA,
            MacAddr::BROADCAST,
        );
        assert_eq!(frame[..24], header.encode(&[])[..24]);
        assert_eq!(frame[24], 0); // SSID IE
        assert_eq!(frame[25], 0); // пустой SSID
    }

    #[test]
    fn builds_beacon_with_ies() {
        let frame = beacon(AP, b"test", 6, 100).unwrap();
        let control = parse_frame_control(&frame).unwrap();
        assert_eq!(control.subtype(), MGMT_BEACON);
        assert!(frame.windows(2).any(|w| w == [0, 4]));
        assert!(frame.ends_with(&[3, 1, 6]));
    }

    #[test]
    fn builds_eapol_data_frames() {
        let eapol = [1, 0, 0, 4, 2, 3, 4, 5];
        let from_ap = eapol_from_ap(STA, AP, &eapol);
        let control = parse_frame_control(&from_ap).unwrap();
        assert_eq!(control.flags(), FC_FLAG_FROM_DS);
        assert!(
            from_ap
                .windows(LLC_SNAP_EAPOL.len())
                .any(|w| w == LLC_SNAP_EAPOL)
        );
        assert!(is_eapol(&from_ap));

        let to_ap = eapol_data(AP, STA, AP, FC_FLAG_TO_DS, &eapol);
        assert!(is_eapol(&to_ap));
        assert!(!is_eapol(&from_ap[..10]));
    }
}
