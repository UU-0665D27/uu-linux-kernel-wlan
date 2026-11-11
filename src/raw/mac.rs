//! MAC-адреса и их текстовое представление.

use std::fmt;
use std::str::FromStr;

use crate::{Error, Result};

/// MAC-адрес из шести октетов.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct MacAddr([u8; 6]);

impl MacAddr {
    /// Широковещательный адрес `ff:ff:ff:ff:ff:ff`.
    pub const BROADCAST: Self = Self([0xff; 6]);

    /// Нулевой адрес `00:00:00:00:00:00`.
    pub const ZERO: Self = Self([0; 6]);

    /// Создаёт адрес из массива октетов.
    #[must_use]
    pub const fn new(octets: [u8; 6]) -> Self {
        Self(octets)
    }

    /// Возвращает октеты адреса.
    #[must_use]
    pub const fn octets(self) -> [u8; 6] {
        self.0
    }

    /// Ссылка на октеты адреса.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 6] {
        &self.0
    }

    /// Возвращает `true`, если адрес широковещательный.
    #[must_use]
    pub fn is_broadcast(self) -> bool {
        self.0 == Self::BROADCAST.0
    }

    /// Возвращает `true`, если выставлен групповой бит.
    #[must_use]
    pub const fn is_multicast(self) -> bool {
        self.0[0] & 1 == 1
    }

    /// Возвращает `true`, если выставлен бит локального администрирования.
    #[must_use]
    pub const fn is_local(self) -> bool {
        self.0[0] & 2 == 2
    }

    /// Разбирает адрес из первых шести байт среза.
    #[must_use]
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        data.get(..6)
            .and_then(|raw| <[u8; 6]>::try_from(raw).ok())
            .map(Self)
    }

    /// Разбирает адрес вида `aa:bb:cc:dd:ee:ff` или `aa-bb-cc-dd-ee-ff`.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let mut octets = [0u8; 6];
        let mut index = 0usize;
        for part in text.split([':', '-']) {
            let slot = octets.get_mut(index)?;
            if part.len() != 2 {
                return None;
            }
            *slot = u8::from_str_radix(part, 16).ok()?;
            index = index.checked_add(1)?;
        }
        if index == octets.len() {
            Some(Self(octets))
        } else {
            None
        }
    }
}

impl From<[u8; 6]> for MacAddr {
    fn from(octets: [u8; 6]) -> Self {
        Self(octets)
    }
}

impl From<MacAddr> for [u8; 6] {
    fn from(address: MacAddr) -> Self {
        address.0
    }
}

impl TryFrom<&[u8]> for MacAddr {
    type Error = Error;

    fn try_from(data: &[u8]) -> Result<Self> {
        Self::from_bytes(data).ok_or_else(|| Error::Mac(format!("{} bytes", data.len())))
    }
}

impl FromStr for MacAddr {
    type Err = Error;

    fn from_str(text: &str) -> Result<Self> {
        Self::parse(text).ok_or_else(|| Error::Mac(text.to_string()))
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [b0, b1, b2, b3, b4, b5] = self.0;
        write!(f, "{b0:02x}:{b1:02x}:{b2:02x}:{b3:02x}:{b4:02x}:{b5:02x}")
    }
}

impl fmt::Debug for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

#[cfg(test)]
mod tests {
    use super::MacAddr;

    #[test]
    fn parses_colon_and_dash_separators() {
        let expected = MacAddr::new([0xaa, 0xbb, 0xcc, 0x11, 0x22, 0x33]);
        assert_eq!(MacAddr::parse("aa:bb:cc:11:22:33"), Some(expected));
        assert_eq!(MacAddr::parse("AA-BB-CC-11-22-33"), Some(expected));
        assert_eq!("aa:bb:cc:11:22:33".parse::<MacAddr>().unwrap(), expected);
    }

    #[test]
    fn rejects_wrong_shapes() {
        assert!(MacAddr::parse("aa:bb:cc:11:22").is_none());
        assert!(MacAddr::parse("aa:bb:cc:11:22:33:44").is_none());
        assert!(MacAddr::parse("aa:bbb:cc:11:22:33").is_none());
        assert!(MacAddr::parse("zz:bb:cc:11:22:33").is_none());
        assert!(MacAddr::parse("").is_none());
    }

    #[test]
    fn formats_lowercase_with_colons() {
        let address = MacAddr::new([0x00, 0x0a, 0x1f, 0x2b, 0x3c, 0x4d]);
        assert_eq!(address.to_string(), "00:0a:1f:2b:3c:4d");
        assert_eq!(format!("{address:?}"), "00:0a:1f:2b:3c:4d");
    }

    #[test]
    fn reports_address_kind() {
        assert!(MacAddr::BROADCAST.is_broadcast());
        assert!(MacAddr::BROADCAST.is_multicast());
        assert!(MacAddr::new([0x01, 0, 0, 0, 0, 0]).is_multicast());
        assert!(!MacAddr::new([0x02, 0, 0, 0, 0, 0]).is_multicast());
        assert!(MacAddr::new([0x02, 0, 0, 0, 0, 0]).is_local());
    }

    #[test]
    fn converts_to_and_from_bytes() {
        let bytes = [1u8, 2, 3, 4, 5, 6];
        let address = MacAddr::from(bytes);
        assert_eq!(address.octets(), bytes);
        assert_eq!(MacAddr::try_from(&bytes[..]).unwrap(), address);
        assert!(MacAddr::try_from(&bytes[..5]).is_err());
    }
}
