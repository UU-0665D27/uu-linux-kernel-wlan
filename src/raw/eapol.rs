//! `EAPOL`/`EAP` и WPS-атрибуты (TLV, big-endian).
//!
//! Слой описывает только разбор и сборку пакетов: state machine WPS
//! (`M1`–`M8`) строится поверх него в высокоуровневом слое.

use crate::{Error, Result};

/// Версия `EAPOL` 802.1X-2001.
pub const EAPOL_VERSION_2001: u8 = 1;
/// Версия `EAPOL` 802.1X-2004.
pub const EAPOL_VERSION_2004: u8 = 2;

/// `EAPOL`-тип `EAP-Packet`.
pub const EAPOL_TYPE_EAP: u8 = 0;
/// `EAPOL`-тип `EAPOL-Start`.
pub const EAPOL_TYPE_START: u8 = 1;
/// `EAPOL`-тип `EAPOL-Logoff`.
pub const EAPOL_TYPE_LOGOFF: u8 = 2;
/// `EAPOL`-тип `EAPOL-Key`.
pub const EAPOL_TYPE_KEY: u8 = 3;
/// `EAPOL`-тип `EAPOL-Encapsulated-ASF-Alert`.
pub const EAPOL_TYPE_ENCRYPTED: u8 = 4;

/// `EAP`-код `Request`.
pub const EAP_REQUEST: u8 = 1;
/// `EAP`-код `Response`.
pub const EAP_RESPONSE: u8 = 2;
/// `EAP`-код `Success`.
pub const EAP_SUCCESS: u8 = 3;
/// `EAP`-код `Failure`.
pub const EAP_FAILURE: u8 = 4;

/// `EAP`-тип `Expanded`.
pub const EAP_TYPE_EXPANDED: u8 = 254;

/// `OUI` WPS (`00:37:2a`).
pub const WPS_VENDOR_ID: [u8; 3] = [0x00, 0x37, 0x2a];
/// Vendor type WPS в `EAP-Expanded`.
pub const WPS_VENDOR_TYPE: u32 = 0x0000_0001;

// ─── WPS-атрибуты ────────────────────────────────────────────────────────────

/// `WPS` `Version`.
pub const WPS_ATTR_VERSION: u16 = 0x104a;
/// `WPS` `Message Type`.
pub const WPS_ATTR_MESSAGE_TYPE: u16 = 0x1022;
/// `WPS` `Enrollee Nonce`.
pub const WPS_ATTR_ENROLLEE_NONCE: u16 = 0x101a;
/// `WPS` `Registrar Nonce`.
pub const WPS_ATTR_REGISTRAR_NONCE: u16 = 0x1019;
/// `WPS` `UUID-E`.
pub const WPS_ATTR_UUID_E: u16 = 0x1047;
/// `WPS` `UUID-R`.
pub const WPS_ATTR_UUID_R: u16 = 0x1048;
/// `WPS` `Public Key`.
pub const WPS_ATTR_PUBLIC_KEY: u16 = 0x1039;
/// `WPS` `Authentication Type Flags`.
pub const WPS_ATTR_AUTH_TYPE_FLAGS: u16 = 0x1004;
/// `WPS` `Encryption Type Flags`.
pub const WPS_ATTR_ENCRYPTION_TYPE_FLAGS: u16 = 0x1010;
/// `WPS` `Connection Type Flags`.
pub const WPS_ATTR_CONNECTION_TYPE_FLAGS: u16 = 0x100c;
/// `WPS` `Configuration Methods`.
pub const WPS_ATTR_CONFIG_METHODS: u16 = 0x1008;
/// `WPS` `WPS State`.
pub const WPS_ATTR_STATE: u16 = 0x1044;
/// `WPS` `AP Setup Locked`.
pub const WPS_ATTR_AP_SETUP_LOCKED: u16 = 0x1057;
/// `WPS` `Manufacturer`.
pub const WPS_ATTR_MANUFACTURER: u16 = 0x1021;
/// `WPS` `Model Name`.
pub const WPS_ATTR_MODEL_NAME: u16 = 0x1023;
/// `WPS` `Model Number`.
pub const WPS_ATTR_MODEL_NUMBER: u16 = 0x1024;
/// `WPS` `Serial Number`.
pub const WPS_ATTR_SERIAL_NUMBER: u16 = 0x1042;
/// `WPS` `Device Name`.
pub const WPS_ATTR_DEVICE_NAME: u16 = 0x1011;
/// `WPS` `Selected Registrar`.
pub const WPS_ATTR_SELECTED_REGISTRAR: u16 = 0x1041;
/// `WPS` `Device Password ID`.
pub const WPS_ATTR_DEVICE_PASSWORD_ID: u16 = 0x1012;
/// `WPS` `RF Bands`.
pub const WPS_ATTR_RF_BANDS: u16 = 0x103c;
/// `WPS` `Response Type`.
pub const WPS_ATTR_RESPONSE_TYPE: u16 = 0x103b;
/// `WPS` `OS Version`.
pub const WPS_ATTR_OS_VERSION: u16 = 0x102d;

/// Значение `WPS_ATTR_MESSAGE_TYPE`: `M1`.
pub const WPS_MSG_M1: u8 = 0x04;
/// Значение `WPS_ATTR_MESSAGE_TYPE`: `M2`.
pub const WPS_MSG_M2: u8 = 0x05;
/// Значение `WPS_ATTR_MESSAGE_TYPE`: `M3`.
pub const WPS_MSG_M3: u8 = 0x07;
/// Значение `WPS_ATTR_MESSAGE_TYPE`: `M4`.
pub const WPS_MSG_M4: u8 = 0x08;
/// Значение `WPS_ATTR_MESSAGE_TYPE`: `M5`.
pub const WPS_MSG_M5: u8 = 0x09;
/// Значение `WPS_ATTR_MESSAGE_TYPE`: `M6`.
pub const WPS_MSG_M6: u8 = 0x0a;
/// Значение `WPS_ATTR_MESSAGE_TYPE`: `M7`.
pub const WPS_MSG_M7: u8 = 0x0b;
/// Значение `WPS_ATTR_MESSAGE_TYPE`: `M8`.
pub const WPS_MSG_M8: u8 = 0x0c;
/// Значение `WPS_ATTR_MESSAGE_TYPE`: `WSC_Start`.
pub const WPS_MSG_START: u8 = 0x01;
/// Значение `WPS_ATTR_MESSAGE_TYPE`: `WSC_Ack`.
pub const WPS_MSG_ACK: u8 = 0x02;
/// Значение `WPS_ATTR_MESSAGE_TYPE`: `WSC_NACK`.
pub const WPS_MSG_NACK: u8 = 0x03;
/// Значение `WPS_ATTR_MESSAGE_TYPE`: `WSC_Done`.
pub const WPS_MSG_DONE: u8 = 0x0f;

/// `WPS` `Device Password ID`: PIN.
pub const WPS_DEVICE_PASSWORD_ID_PIN: u16 = 0x0000;
/// `WPS` `Device Password ID`: push button.
pub const WPS_DEVICE_PASSWORD_ID_PUSH_BUTTON: u16 = 0x0004;

/// Заголовок `EAPOL` и его тело.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Eapol<'a> {
    /// Версия (`EAPOL_VERSION_*`).
    pub version: u8,
    /// Тип пакета (`EAPOL_TYPE_*`).
    pub packet_type: u8,
    /// Тело пакета.
    pub body: &'a [u8],
}

impl<'a> Eapol<'a> {
    /// Разбирает `EAPOL`-пакет.
    #[must_use]
    pub fn parse(data: &'a [u8]) -> Option<Self> {
        let version = *data.first()?;
        let packet_type = *data.get(1)?;
        let declared = usize::from(u16::from_be_bytes(data.get(2..4)?.try_into().ok()?));
        let end = 4usize.checked_add(declared)?;
        let body = data.get(4..end)?;
        Some(Self {
            version,
            packet_type,
            body,
        })
    }

    /// Собирает `EAPOL`-пакет.
    ///
    /// # Errors
    ///
    /// Возвращает [`Error::OutOfRange`], если тело длиннее `65535` байт.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let len = u16::try_from(self.body.len())
            .map_err(|_| Error::OutOfRange(i64::try_from(self.body.len()).unwrap_or(i64::MAX)))?;
        let mut out = Vec::with_capacity(4 + self.body.len());
        out.push(self.version);
        out.push(self.packet_type);
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(self.body);
        Ok(out)
    }
}

/// Собирает `EAPOL`-пакет с указанным типом.
///
/// # Errors
///
/// См. [`Eapol::encode`].
pub fn eapol(packet_type: u8, body: &[u8]) -> Result<Vec<u8>> {
    Eapol {
        version: EAPOL_VERSION_2004,
        packet_type,
        body,
    }
    .encode()
}

/// `EAP`-пакет, содержащий `EAP-Expanded` с vendor-полями.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EapExpanded<'a> {
    /// Код `EAP` (`EAP_REQUEST`, `EAP_RESPONSE`, ...).
    pub code: u8,
    /// Идентификатор запроса.
    pub id: u8,
    /// `OUI` вендора.
    pub vendor_id: [u8; 3],
    /// Vendor type.
    pub vendor_type: u32,
    /// Данные вендора (для WPS — WPS TLVs).
    pub data: &'a [u8],
}

impl<'a> EapExpanded<'a> {
    /// Разбирает `EAP-Expanded` из тела `EAPOL_TYPE_EAP`.
    #[must_use]
    pub fn parse(data: &'a [u8]) -> Option<Self> {
        let code = *data.first()?;
        let id = *data.get(1)?;
        let length = usize::from(u16::from_be_bytes(data.get(2..4)?.try_into().ok()?));
        let packet = data.get(..length)?;
        let body = packet.get(4..)?;
        if body.first().copied()? != EAP_TYPE_EXPANDED {
            return None;
        }
        let payload = body.get(1..)?;
        let vendor_id = <[u8; 3]>::try_from(payload.get(0..3)?).ok()?;
        let vendor_type = u32::from_be_bytes(<[u8; 4]>::try_from(payload.get(3..7)?).ok()?);
        let data = payload.get(7..)?;
        Some(Self {
            code,
            id,
            vendor_id,
            vendor_type,
            data,
        })
    }
}

/// Собирает `EAP-Expanded` пакет.
///
/// # Errors
///
/// Возвращает [`Error::OutOfRange`], если пакет не помещается в `u16`.
pub fn eap_expanded(
    code: u8,
    id: u8,
    vendor_id: [u8; 3],
    vendor_type: u32,
    data: &[u8],
) -> Result<Vec<u8>> {
    let mut body = Vec::with_capacity(8 + data.len());
    body.push(EAP_TYPE_EXPANDED);
    body.extend_from_slice(&vendor_id);
    body.extend_from_slice(&vendor_type.to_be_bytes());
    body.extend_from_slice(data);

    let total = 4usize.checked_add(body.len()).ok_or(Error::Malformed)?;
    let len = u16::try_from(total)
        .map_err(|_| Error::OutOfRange(i64::try_from(total).unwrap_or(i64::MAX)))?;

    let mut out = Vec::with_capacity(total);
    out.push(code);
    out.push(id);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

/// Собирает `EAP-Expanded` с vendor-полями WPS.
///
/// # Errors
///
/// См. [`eap_expanded`].
pub fn wps_eap(code: u8, id: u8, tlvs: &[u8]) -> Result<Vec<u8>> {
    eap_expanded(code, id, WPS_VENDOR_ID, WPS_VENDOR_TYPE, tlvs)
}

/// Один WPS-атрибут.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WpsTlv<'a> {
    /// Тип атрибута (`WPS_ATTR_*`).
    pub kind: u16,
    /// Значение.
    pub value: &'a [u8],
}

/// Итератор по WPS-атрибутам.
#[derive(Debug, Clone)]
pub struct WpsTlvIter<'a> {
    data: &'a [u8],
    position: usize,
}

impl<'a> WpsTlvIter<'a> {
    /// Создаёт итератор по буферу WPS-атрибутов.
    #[must_use]
    pub const fn new(data: &'a [u8]) -> Self {
        Self { data, position: 0 }
    }
}

impl<'a> Iterator for WpsTlvIter<'a> {
    type Item = WpsTlv<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let header = self
            .data
            .get(self.position..self.position.checked_add(4)?)?;
        let kind = u16::from_be_bytes(<[u8; 2]>::try_from(header.get(0..2)?).ok()?);
        let len = usize::from(u16::from_be_bytes(
            <[u8; 2]>::try_from(header.get(2..4)?).ok()?,
        ));
        let start = self.position.checked_add(4)?;
        let end = start.checked_add(len)?;
        let value = self.data.get(start..end)?;
        self.position = end;
        Some(WpsTlv { kind, value })
    }
}

/// Находит первый WPS-атрибут указанного типа.
#[must_use]
pub fn find_tlv(data: &[u8], kind: u16) -> Option<&[u8]> {
    WpsTlvIter::new(data)
        .find(|tlv| tlv.kind == kind)
        .map(|tlv| tlv.value)
}

/// Строитель WPS-атрибутов.
#[derive(Debug, Clone, Default)]
pub struct WpsTlvWriter {
    buffer: Vec<u8>,
}

impl WpsTlvWriter {
    /// Создаёт пустой строитель.
    #[must_use]
    pub const fn new() -> Self {
        Self { buffer: Vec::new() }
    }

    /// Добавляет атрибут с произвольным значением.
    ///
    /// # Errors
    ///
    /// Возвращает [`Error::OutOfRange`], если значение длиннее `65535` байт.
    pub fn push(&mut self, kind: u16, value: &[u8]) -> Result<()> {
        let len = u16::try_from(value.len())
            .map_err(|_| Error::OutOfRange(i64::try_from(value.len()).unwrap_or(i64::MAX)))?;
        self.buffer.extend_from_slice(&kind.to_be_bytes());
        self.buffer.extend_from_slice(&len.to_be_bytes());
        self.buffer.extend_from_slice(value);
        Ok(())
    }

    /// Добавляет однобайтовый атрибут.
    ///
    /// # Errors
    ///
    /// См. [`WpsTlvWriter::push`].
    pub fn u8(&mut self, kind: u16, value: u8) -> Result<()> {
        self.push(kind, &[value])
    }

    /// Добавляет двухбайтовый атрибут в big-endian.
    ///
    /// # Errors
    ///
    /// См. [`WpsTlvWriter::push`].
    pub fn u16(&mut self, kind: u16, value: u16) -> Result<()> {
        self.push(kind, &value.to_be_bytes())
    }

    /// Добавляет четырёхбайтовый атрибут в big-endian.
    ///
    /// # Errors
    ///
    /// См. [`WpsTlvWriter::push`].
    pub fn u32(&mut self, kind: u16, value: u32) -> Result<()> {
        self.push(kind, &value.to_be_bytes())
    }

    /// Возвращает накопленные байты.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.buffer
    }

    /// Забирает накопленные байты.
    #[must_use]
    pub fn finish(self) -> Vec<u8> {
        self.buffer
    }
}

/// Читает `u16` из WPS-значения в big-endian.
#[must_use]
pub fn read_be_u16(value: &[u8]) -> Option<u16> {
    value
        .get(0..2)
        .and_then(|raw| <[u8; 2]>::try_from(raw).ok())
        .map(u16::from_be_bytes)
}

/// Читает `u32` из WPS-значения в big-endian.
#[must_use]
pub fn read_be_u32(value: &[u8]) -> Option<u32> {
    value
        .get(0..4)
        .and_then(|raw| <[u8; 4]>::try_from(raw).ok())
        .map(u32::from_be_bytes)
}

#[cfg(test)]
mod tests {
    use super::{
        EAP_REQUEST, EAP_RESPONSE, EapExpanded, Eapol, WPS_ATTR_MESSAGE_TYPE, WPS_ATTR_VERSION,
        WPS_MSG_M1, WPS_VENDOR_ID, WPS_VENDOR_TYPE, WpsTlvIter, WpsTlvWriter, eapol, find_tlv,
        read_be_u16, wps_eap,
    };

    #[test]
    fn roundtrips_eapol() {
        let raw = eapol(super::EAPOL_TYPE_EAP, &[1, 2, 3]).unwrap();
        let parsed = Eapol::parse(&raw).unwrap();
        assert_eq!(parsed.packet_type, super::EAPOL_TYPE_EAP);
        assert_eq!(parsed.body, [1, 2, 3]);
        assert!(Eapol::parse(&raw[..2]).is_none());
    }

    #[test]
    fn builds_and_parses_wps_eap() {
        let mut tlvs = WpsTlvWriter::new();
        tlvs.u8(WPS_ATTR_VERSION, 0x10).unwrap();
        tlvs.u8(WPS_ATTR_MESSAGE_TYPE, WPS_MSG_M1).unwrap();
        let tlvs = tlvs.finish();

        let raw = wps_eap(EAP_REQUEST, 7, &tlvs).unwrap();
        let parsed = EapExpanded::parse(&raw).unwrap();
        assert_eq!(parsed.code, EAP_REQUEST);
        assert_eq!(parsed.id, 7);
        assert_eq!(parsed.vendor_id, WPS_VENDOR_ID);
        assert_eq!(parsed.vendor_type, WPS_VENDOR_TYPE);
        assert_eq!(
            find_tlv(parsed.data, WPS_ATTR_MESSAGE_TYPE),
            Some(&[WPS_MSG_M1][..])
        );
    }

    #[test]
    fn rejects_non_expanded_eap() {
        let raw = [EAP_RESPONSE, 1, 0, 5, 1];
        assert!(EapExpanded::parse(&raw).is_none());
    }

    #[test]
    fn iterates_wps_tlvs() {
        let mut writer = WpsTlvWriter::new();
        writer.u16(WPS_ATTR_VERSION, 0x0010).unwrap();
        writer.u8(WPS_ATTR_MESSAGE_TYPE, WPS_MSG_M1).unwrap();
        let raw = writer.finish();

        let tlvs: Vec<_> = WpsTlvIter::new(&raw).collect();
        assert_eq!(tlvs.len(), 2);
        assert_eq!(read_be_u16(tlvs[0].value), Some(0x0010));
        assert_eq!(tlvs[1].value, [WPS_MSG_M1]);
    }

    #[test]
    fn stops_on_truncated_tlv() {
        assert_eq!(WpsTlvIter::new(&[0x10, 0x4a, 0x00]).count(), 0);
        assert_eq!(WpsTlvIter::new(&[0x10, 0x4a, 0x00, 0x04, 0x00]).count(), 0);
    }
}
