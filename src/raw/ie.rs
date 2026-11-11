//! Информационные элементы (`Information Element`) 802.11.
//!
//! Формат: `id: u8`, `length: u8`, `body: [u8; length]`.

use crate::{Error, Result};

/// Информационный элемент `SSID`.
pub const IE_SSID: u8 = 0;
/// Информационный элемент поддерживаемых скоростей.
pub const IE_SUPPORTED_RATES: u8 = 1;
/// Информационный элемент `DS Parameter Set` (номер канала).
pub const IE_DS_PARAMETER: u8 = 3;
/// Информационный элемент `TIM`.
pub const IE_TIM: u8 = 5;
/// Информационный элемент `Country`.
pub const IE_COUNTRY: u8 = 7;
/// Информационный элемент `HT Capabilities`.
pub const IE_HT_CAPABILITIES: u8 = 45;
/// Информационный элемент `RSN`.
pub const IE_RSN: u8 = 48;
/// Информационный элемент `HT Operation`.
pub const IE_HT_OPERATION: u8 = 61;
/// Информационный элемент `Vendor Specific`.
pub const IE_VENDOR: u8 = 221;
/// Информационный элемент расширения.
pub const IE_EXTENSION: u8 = 255;

/// `OUI` Microsoft, используемый WPS.
pub const WPS_OUI: [u8; 3] = [0x00, 0x50, 0xf2];
/// Тип `OUI` для WPS.
pub const WPS_OUI_TYPE: u8 = 0x04;
/// Заголовок vendor-элемента WPS: `OUI` + тип.
pub const WPS_VENDOR_HEADER: [u8; 4] = [WPS_OUI[0], WPS_OUI[1], WPS_OUI[2], WPS_OUI_TYPE];

/// Один информационный элемент.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ie<'a> {
    /// Идентификатор элемента.
    pub id: u8,
    /// Тело элемента.
    pub body: &'a [u8],
}

/// Итератор по информационным элементам.
#[derive(Debug, Clone)]
pub struct IeIter<'a> {
    data: &'a [u8],
    position: usize,
}

impl<'a> IeIter<'a> {
    /// Создаёт итератор по буферу элементов.
    #[must_use]
    pub const fn new(data: &'a [u8]) -> Self {
        Self { data, position: 0 }
    }
}

impl<'a> Iterator for IeIter<'a> {
    type Item = Ie<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let header = self
            .data
            .get(self.position..self.position.checked_add(2)?)?;
        let id = *header.first()?;
        let len = usize::from(*header.get(1)?);
        let start = self.position.checked_add(2)?;
        let end = start.checked_add(len)?;
        let body = self.data.get(start..end)?;
        self.position = end;
        Some(Ie { id, body })
    }
}

/// Находит первый элемент с указанным идентификатором.
#[must_use]
pub fn find(data: &[u8], id: u8) -> Option<Ie<'_>> {
    IeIter::new(data).find(|element| element.id == id)
}

/// Ищет vendor-элемент WPS.
#[must_use]
pub fn find_wps(data: &[u8]) -> Option<Ie<'_>> {
    IeIter::new(data)
        .find(|element| element.id == IE_VENDOR && element.body.starts_with(&WPS_VENDOR_HEADER))
}

/// Строитель набора информационных элементов.
#[derive(Debug, Clone, Default)]
pub struct IeList {
    buffer: Vec<u8>,
}

impl IeList {
    /// Создаёт пустой набор.
    #[must_use]
    pub const fn new() -> Self {
        Self { buffer: Vec::new() }
    }

    /// Добавляет элемент с произвольным телом.
    ///
    /// # Errors
    ///
    /// Возвращает [`Error::Message`], если тело длиннее `255` байт.
    pub fn push(&mut self, id: u8, body: &[u8]) -> Result<()> {
        let len = u8::try_from(body.len())
            .map_err(|_| Error::Message(format!("IE {id} body is too long")))?;
        self.buffer.push(id);
        self.buffer.push(len);
        self.buffer.extend_from_slice(body);
        Ok(())
    }

    /// Добавляет элемент `SSID`.
    ///
    /// # Errors
    ///
    /// Возвращает ошибку, если SSID длиннее `255` байт.
    pub fn ssid(&mut self, ssid: &[u8]) -> Result<()> {
        self.push(IE_SSID, ssid)
    }

    /// Добавляет элемент поддерживаемых скоростей.
    ///
    /// # Errors
    ///
    /// Возвращает ошибку, если список длиннее `255` байт.
    pub fn rates(&mut self, rates: &[u8]) -> Result<()> {
        self.push(IE_SUPPORTED_RATES, rates)
    }

    /// Добавляет элемент `DS Parameter Set`.
    ///
    /// # Errors
    ///
    /// Возвращает ошибку при переполнении буфера.
    pub fn ds_parameter(&mut self, channel: u8) -> Result<()> {
        self.push(IE_DS_PARAMETER, &[channel])
    }

    /// Добавляет vendor-элемент.
    ///
    /// # Errors
    ///
    /// Возвращает ошибку, если тело длиннее `255` байт.
    pub fn vendor(&mut self, oui: [u8; 3], body: &[u8]) -> Result<()> {
        let mut data = Vec::with_capacity(3 + body.len());
        data.extend_from_slice(&oui);
        data.extend_from_slice(body);
        self.push(IE_VENDOR, &data)
    }

    /// Добавляет vendor-элемент WPS.
    ///
    /// # Errors
    ///
    /// Возвращает ошибку, если тело длиннее `251` байта.
    pub fn wps(&mut self, body: &[u8]) -> Result<()> {
        let mut data = Vec::with_capacity(WPS_VENDOR_HEADER.len() + body.len());
        data.extend_from_slice(&WPS_VENDOR_HEADER);
        data.extend_from_slice(body);
        self.push(IE_VENDOR, &data)
    }

    /// Возвращает накопленные байты.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.buffer
    }

    /// Возвращает `true`, если элементов нет.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    /// Забирает накопленные байты.
    #[must_use]
    pub fn finish(self) -> Vec<u8> {
        self.buffer
    }
}

#[cfg(test)]
mod tests {
    use super::{IE_DS_PARAMETER, IE_RSN, IE_SSID, IE_VENDOR, IeIter, IeList, find, find_wps};

    #[test]
    fn iterates_and_finds_elements() {
        let data = [
            IE_SSID,
            3,
            b'a',
            b'b',
            b'c',
            IE_RSN,
            0,
            IE_DS_PARAMETER,
            1,
            6,
        ];
        let elements: Vec<_> = IeIter::new(&data).collect();
        assert_eq!(elements.len(), 3);
        assert_eq!(elements[0].id, IE_SSID);
        assert_eq!(elements[0].body, b"abc");

        let ssid = find(&data, IE_SSID).unwrap();
        assert_eq!(ssid.body, b"abc");
        assert!(find(&data, 99).is_none());
    }

    #[test]
    fn stops_on_truncated_element() {
        let data = [IE_SSID, 4, b'a', b'b'];
        assert_eq!(IeIter::new(&data).count(), 0);
    }

    #[test]
    fn builds_elements() {
        let mut list = IeList::new();
        list.ssid(b"home").unwrap();
        list.ds_parameter(6).unwrap();
        let raw = list.finish();

        let elements: Vec<_> = IeIter::new(&raw).collect();
        assert_eq!(elements.len(), 2);
        assert_eq!(elements[0].body, b"home");
        assert_eq!(elements[1].body, [6]);
    }

    #[test]
    fn rejects_oversized_body() {
        let mut list = IeList::new();
        assert!(list.push(IE_SSID, &vec![0u8; 256]).is_err());
    }

    #[test]
    fn finds_wps_vendor_element() {
        let mut list = IeList::new();
        list.vendor([0x00, 0x11, 0x22], b"x").unwrap();
        list.wps(&[0x10, 0x4a, 0x00, 0x01, 0x10]).unwrap();
        let raw = list.finish();

        let wps = find_wps(&raw).unwrap();
        assert_eq!(wps.id, IE_VENDOR);
        assert!(wps.body.starts_with(&super::WPS_VENDOR_HEADER));
        assert_eq!(super::WPS_OUI, [0x00, 0x50, 0xf2]);
    }
}
