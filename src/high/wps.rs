//! WPS: разбор vendor-элемента и генерация PIN по `BSSID`.
//!
//! Для генерации используется крейт `uu-wlan-wps-pin-gen`. Никакой базы
//! `OUI` в памяти не держится: в генераторе только короткие списки
//! префиксов производителей.

use crate::raw::eapol::{
    WPS_ATTR_AP_SETUP_LOCKED, WPS_ATTR_CONFIG_METHODS, WPS_ATTR_DEVICE_NAME,
    WPS_ATTR_DEVICE_PASSWORD_ID, WPS_ATTR_MANUFACTURER, WPS_ATTR_MODEL_NAME, WPS_ATTR_MODEL_NUMBER,
    WPS_ATTR_OS_VERSION, WPS_ATTR_RESPONSE_TYPE, WPS_ATTR_RF_BANDS, WPS_ATTR_SELECTED_REGISTRAR,
    WPS_ATTR_SERIAL_NUMBER, WPS_ATTR_STATE, WPS_ATTR_UUID_E, WPS_ATTR_VERSION, WpsTlvIter,
    read_be_u16, read_be_u32,
};
use crate::raw::ie::{IE_VENDOR, IeIter, WPS_VENDOR_HEADER};
use crate::raw::mac::MacAddr;

/// Разобранный WPS-элемент точки доступа.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WpsIe {
    /// Версия WPS.
    pub version: Option<u16>,
    /// Состояние (`WPS State`).
    pub state: Option<u8>,
    /// `AP Setup Locked`.
    pub ap_setup_locked: Option<bool>,
    /// Способы конфигурации.
    pub config_methods: Option<u16>,
    /// `Device Password ID`.
    pub device_password_id: Option<u16>,
    /// `Selected Registrar`.
    pub selected_registrar: Option<bool>,
    /// `Response Type`.
    pub response_type: Option<u8>,
    /// `UUID-E`.
    pub uuid_e: Option<[u8; 16]>,
    /// `RF Bands`.
    pub rf_bands: Option<u8>,
    /// `OS Version`.
    pub os_version: Option<u32>,
    /// Производитель.
    pub manufacturer: Option<String>,
    /// Модель.
    pub model_name: Option<String>,
    /// Номер модели.
    pub model_number: Option<String>,
    /// Имя устройства.
    pub device_name: Option<String>,
    /// Серийный номер.
    pub serial_number: Option<String>,
}

impl WpsIe {
    /// Разбирает WPS-атрибуты (тело vendor-элемента без `OUI` и типа).
    #[must_use]
    pub fn parse(tlvs: &[u8]) -> Self {
        let mut wps = Self::default();
        for tlv in WpsTlvIter::new(tlvs) {
            match tlv.kind {
                WPS_ATTR_VERSION => wps.version = read_be_u16(tlv.value),
                WPS_ATTR_STATE => wps.state = tlv.value.first().copied(),
                WPS_ATTR_AP_SETUP_LOCKED => {
                    wps.ap_setup_locked = tlv.value.first().map(|value| *value != 0);
                }
                WPS_ATTR_CONFIG_METHODS => wps.config_methods = read_be_u16(tlv.value),
                WPS_ATTR_DEVICE_PASSWORD_ID => wps.device_password_id = read_be_u16(tlv.value),
                WPS_ATTR_SELECTED_REGISTRAR => {
                    wps.selected_registrar = tlv.value.first().map(|value| *value != 0);
                }
                WPS_ATTR_RESPONSE_TYPE => wps.response_type = tlv.value.first().copied(),
                WPS_ATTR_UUID_E => {
                    wps.uuid_e = tlv
                        .value
                        .get(0..16)
                        .and_then(|raw| <[u8; 16]>::try_from(raw).ok());
                }
                WPS_ATTR_RF_BANDS => wps.rf_bands = tlv.value.first().copied(),
                WPS_ATTR_OS_VERSION => wps.os_version = read_be_u32(tlv.value),
                WPS_ATTR_MANUFACTURER => wps.manufacturer = text(tlv.value),
                WPS_ATTR_MODEL_NAME => wps.model_name = text(tlv.value),
                WPS_ATTR_MODEL_NUMBER => wps.model_number = text(tlv.value),
                WPS_ATTR_DEVICE_NAME => wps.device_name = text(tlv.value),
                WPS_ATTR_SERIAL_NUMBER => wps.serial_number = text(tlv.value),
                _ => {}
            }
        }
        wps
    }

    /// Разбирает vendor-элемент WPS, если он есть в наборе IE.
    #[must_use]
    pub fn from_vendor_body(body: &[u8]) -> Option<Self> {
        let tlvs = body.strip_prefix(WPS_VENDOR_HEADER.as_slice())?;
        Some(Self::parse(tlvs))
    }

    /// Ищет и разбирает WPS-элемент в буфере информационных элементов.
    #[must_use]
    pub fn find_in_ies(ies: &[u8]) -> Option<Self> {
        for element in IeIter::new(ies) {
            if element.id == IE_VENDOR
                && let Some(wps) = Self::from_vendor_body(element.body)
            {
                return Some(wps);
            }
        }
        None
    }

    /// Возвращает `true`, если точка доступа сообщает о включённом WPS.
    #[must_use]
    pub const fn is_enabled(&self) -> bool {
        self.version.is_some()
    }

    /// Возвращает `true`, если WPS заблокирован настройками AP.
    #[must_use]
    pub fn is_locked(&self) -> bool {
        self.ap_setup_locked.unwrap_or(false)
    }
}

fn text(value: &[u8]) -> Option<String> {
    if value.is_empty() {
        return None;
    }
    Some(String::from_utf8_lossy(value).into_owned())
}

/// Генерирует все известные PIN-коды для `BSSID`.
///
/// Возвращает пустой список, если MAC некорректен. Порядок соответствует
/// `generate_all_pins` из `uu-wlan-wps-pin-gen`, дубликаты удаляются.
#[must_use]
pub fn pin_candidates(bssid: MacAddr) -> Vec<String> {
    let all = uu_wlan_wps_pin_gen::generate_all_pins(&bssid.to_string());
    let mut result = Vec::new();
    for pin in [
        all.pin1, all.pin2, all.pin3, all.pin4, all.pin5, all.pin6, all.pin7, all.pin8, all.pin9,
        all.pin10,
    ]
    .into_iter()
    .flatten()
    {
        if !result.contains(&pin) {
            result.push(pin);
        }
    }
    trace!(bssid = %bssid, count = result.len(), "WPS pin candidates");
    result
}

/// Генерирует 4 основных и 6 дополнительных PIN, как в приложении.
#[must_use]
pub fn app_pin_candidates(bssid: MacAddr) -> Option<Vec<String>> {
    let app = uu_wlan_wps_pin_gen::generate_app_pins(&bssid.to_string())?;
    let mut result = Vec::with_capacity(10);
    result.extend(app.main);
    result.extend(app.more);
    Some(result)
}

#[cfg(test)]
mod tests {
    use super::WpsIe;
    use crate::raw::eapol::{
        WPS_ATTR_DEVICE_NAME, WPS_ATTR_STATE, WPS_ATTR_VERSION, WPS_VENDOR_ID, WPS_VENDOR_TYPE,
        WpsTlvWriter,
    };
    use crate::raw::ie::{IeList, WPS_OUI, WPS_OUI_TYPE};

    #[test]
    fn parses_wps_tlvs() {
        let mut writer = WpsTlvWriter::new();
        writer.u16(WPS_ATTR_VERSION, 0x0010).unwrap();
        writer.u8(WPS_ATTR_STATE, 2).unwrap();
        writer.push(WPS_ATTR_DEVICE_NAME, b"router").unwrap();
        let wps = WpsIe::parse(&writer.finish());

        assert_eq!(wps.version, Some(0x0010));
        assert_eq!(wps.state, Some(2));
        assert_eq!(wps.device_name.as_deref(), Some("router"));
        assert!(wps.is_enabled());
        assert!(!wps.is_locked());
    }

    #[test]
    fn finds_wps_ie_in_beacon() {
        let mut writer = WpsTlvWriter::new();
        writer.u16(WPS_ATTR_VERSION, 0x0010).unwrap();
        let tlvs = writer.finish();

        let mut elements = IeList::new();
        elements.ssid(b"test").unwrap();
        elements.wps(&tlvs).unwrap();

        let wps = WpsIe::find_in_ies(elements.as_bytes()).unwrap();
        assert_eq!(wps.version, Some(0x0010));
    }

    #[test]
    fn ignores_non_wps_vendor_ie() {
        let mut elements = IeList::new();
        elements.vendor([0x00, 0x11, 0x22], b"x").unwrap();
        assert!(WpsIe::find_in_ies(elements.as_bytes()).is_none());
    }

    #[test]
    fn generates_pins_for_bssid() {
        let bssid = "00:11:22:33:44:55".parse().unwrap();
        let pins = super::pin_candidates(bssid);
        assert_ne!(pins.len(), 0);
        assert!(pins.iter().all(|pin| pin.len() == 8));
        assert!(super::app_pin_candidates(bssid).is_some());
    }

    #[test]
    fn constants_match_wps() {
        assert_eq!(WPS_VENDOR_ID, [0x00, 0x37, 0x2a]);
        assert_eq!(WPS_VENDOR_TYPE, 1);
        assert_eq!(WPS_OUI, [0x00, 0x50, 0xf2]);
        assert_eq!(WPS_OUI_TYPE, 4);
    }
}
