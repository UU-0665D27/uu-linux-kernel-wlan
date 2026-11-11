//! Сканирование эфира: триггер, ожидание и разбор результатов nl80211.
//!
//! Помимо `scan()`/`scan_results()` есть потоковый `scan_each()`: он не
//! накапливает все сети в памяти и подходит для устройств с малым объёмом
//! ОЗУ.

use std::time::Duration;

use uu_linux_kernel_netlink::{AttrIter, AttrWriter, read_mac, read_u32};

use crate::high::nl80211_ext::{
    ATTR_BSS, ATTR_IFINDEX, ATTR_SCAN_FLAGS, ATTR_SCAN_FREQUENCIES, ATTR_SCAN_SSIDS,
    BSS_BEACON_IES, BSS_BSSID, BSS_FREQUENCY, BSS_INFORMATION_ELEMENTS, BSS_SEEN_MS_AGO,
    BSS_SIGNAL_MBM, BSS_STATUS, CMD_GET_SCAN, CMD_TRIGGER_SCAN, SCAN_FLAG_FLUSH,
};
use crate::high::wps::{WpsIe, pin_candidates};
use crate::raw::ie::{IE_SSID, find};
use crate::raw::mac::MacAddr;
use crate::{Error, Result};

/// Ожидание результатов сканирования по умолчанию.
pub const DEFAULT_SCAN_WAIT: Duration = Duration::from_secs(3);

/// Одна найденная сеть (`BSS`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bss {
    /// `BSSID` точки доступа.
    pub bssid: MacAddr,
    /// Частота в `МГц`.
    pub frequency: u32,
    /// `SSID`, если он передан в информационных элементах.
    pub ssid: Option<String>,
    /// Уровень сигнала в `дБм`.
    pub signal_dbm: Option<i32>,
    /// Статус подключения (`NL80211_BSS_STATUS_*`).
    pub status: Option<u32>,
    /// Сколько миллисекунд назад сеть была замечена.
    pub seen_ms_ago: Option<u32>,
    /// Информационные элементы beacon/probe response.
    pub ies: Vec<u8>,
    /// Разобранный WPS-элемент.
    pub wps: Option<WpsIe>,
}

impl Bss {
    /// Разбирает вложенный атрибут `NL80211_ATTR_BSS`.
    #[must_use]
    pub fn parse(data: &[u8]) -> Option<Self> {
        let mut bssid = None;
        let mut frequency = None;
        let mut ies = Vec::new();
        let mut signal_mbm = None;
        let mut status = None;
        let mut seen_ms_ago = None;

        for (kind, value) in AttrIter::new(data) {
            match kind {
                BSS_BSSID => bssid = read_mac(value).map(MacAddr::new),
                BSS_FREQUENCY => frequency = read_u32(value),
                BSS_INFORMATION_ELEMENTS => ies = value.to_vec(),
                BSS_BEACON_IES => {
                    if ies.is_empty() {
                        ies = value.to_vec();
                    }
                }
                BSS_SIGNAL_MBM => {
                    signal_mbm = read_u32(value).map(|raw| i32::from_ne_bytes(raw.to_ne_bytes()));
                }
                BSS_STATUS => status = read_u32(value),
                BSS_SEEN_MS_AGO => seen_ms_ago = read_u32(value),
                _ => {}
            }
        }

        let ssid = find(&ies, IE_SSID)
            .filter(|element| !element.body.is_empty())
            .map(|element| String::from_utf8_lossy(element.body).into_owned());
        let wps = WpsIe::find_in_ies(&ies);

        Some(Self {
            bssid: bssid?,
            frequency: frequency?,
            ssid,
            signal_dbm: signal_mbm.map(|value| value / 100),
            status,
            seen_ms_ago,
            ies,
            wps,
        })
    }

    /// Номер канала, соответствующий частоте.
    #[must_use]
    pub fn channel(&self) -> Option<u8> {
        frequency_to_channel(self.frequency)
    }

    /// Возвращает `true`, если в beacon есть WPS-элемент.
    #[must_use]
    pub const fn is_wps(&self) -> bool {
        self.wps.is_some()
    }

    /// Генерирует PIN-коды WPS по `BSSID`.
    #[must_use]
    pub fn wps_pins(&self) -> Vec<String> {
        pin_candidates(self.bssid)
    }

    /// Генерирует PIN-коды в порядке приложения (4 + 6).
    #[must_use]
    pub fn wps_app_pins(&self) -> Option<Vec<String>> {
        crate::high::wps::app_pin_candidates(self.bssid)
    }
}

impl std::fmt::Display for Bss {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let ssid = self.ssid.as_deref().unwrap_or("<hidden>");
        let signal = self
            .signal_dbm
            .map_or_else(|| "?".to_string(), |value| value.to_string());
        write!(
            f,
            "{}  {:>4} MHz  {:>4} dBm  {}{}",
            self.bssid,
            self.frequency,
            signal,
            ssid,
            if self.is_wps() { "  [WPS]" } else { "" },
        )
    }
}

/// Переводит частоту в номер канала.
#[must_use]
pub fn frequency_to_channel(frequency: u32) -> Option<u8> {
    uu_linux_kernel_netlink::all_channels()
        .into_iter()
        .find(|(_, value)| *value == frequency)
        .map(|(channel, _)| channel)
}

impl crate::high::Wlan {
    /// Запускает сканирование.
    ///
    /// Пустой срез `frequencies` означает все каналы.
    ///
    /// # Errors
    ///
    /// Возвращает ошибку netlink, если драйвер отклонил запрос.
    pub fn trigger_scan(&mut self, frequencies: &[u32]) -> Result<()> {
        let mut attrs = AttrWriter::new();
        attrs.u32(ATTR_IFINDEX, self.iface().index);
        // Пустой вложенный список SSID — сканирование всех сетей.
        attrs.nested(ATTR_SCAN_SSIDS, |_| {});
        if !frequencies.is_empty() {
            attrs.nested(ATTR_SCAN_FREQUENCIES, |nested| {
                for (index, frequency) in frequencies.iter().enumerate() {
                    if let Ok(attr_type) = u16::try_from(index) {
                        nested.u32(attr_type, *frequency);
                    }
                }
            });
        }
        attrs.u32(ATTR_SCAN_FLAGS, SCAN_FLAG_FLUSH);

        let family = self.nl().family_id();
        self.nl_mut()
            .genl_mut()
            .execute(family, CMD_TRIGGER_SCAN, 0, &attrs)?;
        trace!(count = frequencies.len(), "scan triggered");
        Ok(())
    }

    /// Возвращает накопленные результаты сканирования.
    ///
    /// # Errors
    ///
    /// Возвращает ошибку dump-запроса `NL80211_CMD_GET_SCAN`.
    pub fn scan_results(&mut self) -> Result<Vec<Bss>> {
        let mut result = Vec::new();
        self.scan_each(|bss| result.push(bss))?;
        Ok(result)
    }

    /// Передаёт каждую найденную сеть в `visit`, не собирая их в список.
    ///
    /// # Errors
    ///
    /// Возвращает ошибку dump-запроса `NL80211_CMD_GET_SCAN`.
    pub fn scan_each<F>(&mut self, mut visit: F) -> Result<()>
    where
        F: FnMut(Bss),
    {
        let mut attrs = AttrWriter::new();
        attrs.u32(ATTR_IFINDEX, self.iface().index);
        let family = self.nl().family_id();
        self.nl_mut()
            .genl_mut()
            .dump_each(family, CMD_GET_SCAN, 0, &attrs, |message| {
                for (kind, value) in message.attrs() {
                    if kind == ATTR_BSS
                        && let Some(bss) = Bss::parse(value)
                    {
                        visit(bss);
                    }
                }
                Ok(())
            })?;
        Ok(())
    }

    /// Запускает сканирование, ждёт и возвращает результаты.
    ///
    /// # Errors
    ///
    /// Возвращает ошибку запуска или чтения результатов.
    pub fn scan(&mut self) -> Result<Vec<Bss>> {
        self.scan_with(DEFAULT_SCAN_WAIT)
    }

    /// Запускает сканирование и ждёт указанное время.
    ///
    /// # Errors
    ///
    /// Возвращает ошибку запуска или чтения результатов.
    pub fn scan_with(&mut self, wait: Duration) -> Result<Vec<Bss>> {
        self.trigger_scan(&[])?;
        trace!(?wait, "waiting for scan");
        std::thread::sleep(wait);
        self.scan_results()
    }

    /// Запускает сканирование и вызывает `visit` для каждой сети.
    ///
    /// # Errors
    ///
    /// Возвращает ошибку запуска или чтения результатов.
    pub fn scan_each_with<F>(&mut self, wait: Duration, visit: F) -> Result<()>
    where
        F: FnMut(Bss),
    {
        self.trigger_scan(&[])?;
        trace!(?wait, "waiting for scan");
        std::thread::sleep(wait);
        self.scan_each(visit)
    }
}

/// Проверяет, что частота лежит в известном диапазоне.
///
/// # Errors
///
/// Возвращает [`Error::OutOfRange`] для неподдерживаемой частоты.
pub fn validate_frequency(frequency: u32) -> Result<u32> {
    if frequency_to_channel(frequency).is_some() {
        Ok(frequency)
    } else {
        Err(Error::OutOfRange(i64::from(frequency)))
    }
}

#[cfg(test)]
mod tests {
    use super::{Bss, frequency_to_channel};
    use crate::high::nl80211_ext::{
        ATTR_BSS, BSS_BSSID, BSS_FREQUENCY, BSS_INFORMATION_ELEMENTS, BSS_SIGNAL_MBM, BSS_STATUS,
    };
    use uu_linux_kernel_netlink::{AttrWriter, MessageBuilder, NLM_F_MULTI, NlMessage};

    fn bss_message(ies: &[u8]) -> NlMessage {
        let mut inner = AttrWriter::new();
        inner.bytes(BSS_BSSID, &[0x02, 0x11, 0x22, 0x33, 0x44, 0x55]);
        inner.u32(BSS_FREQUENCY, 2437);
        inner.bytes(BSS_INFORMATION_ELEMENTS, ies);
        inner.u32(BSS_SIGNAL_MBM, u32::from_ne_bytes((-4200i32).to_ne_bytes()));
        inner.u32(BSS_STATUS, 1);

        let mut outer = AttrWriter::new();
        outer.nested(ATTR_BSS, |nested| nested.extend(inner.as_bytes()));

        let raw = MessageBuilder::genl(1, 0x13, libc::NLM_F_REQUEST | NLM_F_MULTI, 32, 0)
            .attrs(&outer)
            .finish()
            .unwrap();
        NlMessage::parse(raw).unwrap()
    }

    #[test]
    fn parses_bss_attributes() {
        let mut ies = Vec::new();
        ies.extend_from_slice(&[0, 4, b't', b'e', b's', b't']);
        let message = bss_message(&ies);

        let mut parsed = None;
        for (kind, value) in message.attrs() {
            if kind == ATTR_BSS {
                parsed = Bss::parse(value);
            }
        }
        let bss = parsed.unwrap();
        assert_eq!(bss.ssid.as_deref(), Some("test"));
        assert_eq!(bss.frequency, 2437);
        assert_eq!(bss.channel(), Some(6));
        assert_eq!(bss.signal_dbm, Some(-42));
        assert!(!bss.is_wps());
    }

    #[test]
    fn maps_frequencies_to_channels() {
        assert_eq!(frequency_to_channel(2412), Some(1));
        assert_eq!(frequency_to_channel(5180), Some(36));
        assert_eq!(frequency_to_channel(1234), None);
    }

    #[test]
    fn rejects_bss_without_address() {
        let mut inner = AttrWriter::new();
        inner.u32(BSS_FREQUENCY, 2437);
        assert!(Bss::parse(inner.as_bytes()).is_none());
    }
}
