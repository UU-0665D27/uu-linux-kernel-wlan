//! Заголовок `radiotap`: поля скорости, канала и TX-флагов.
//!
//! Все многобайтовые поля radiotap хранятся в порядке little-endian.

/// Версия заголовка radiotap.
pub const RADIOTAP_VERSION: u8 = 0;

/// Минимальная длина заголовка без полей.
pub const RADIOTAP_MIN_LEN: usize = 8;

/// Бит `RATE` в битовой карте присутствующих полей.
pub const RADIOTAP_F_RATE: u32 = 1 << 2;
/// Бит `CHANNEL` в битовой карте присутствующих полей.
pub const RADIOTAP_F_CHANNEL: u32 = 1 << 3;
/// Бит `TX_FLAGS` в битовой карте присутствующих полей.
pub const RADIOTAP_F_TX_FLAGS: u32 = 1 << 15;

/// Флаг канала `CCK`.
pub const CHAN_CCK: u16 = 0x0020;
/// Флаг канала `OFDM`.
pub const CHAN_OFDM: u16 = 0x0040;
/// Флаг диапазона `2.4 ГГц`.
pub const CHAN_2GHZ: u16 = 0x0080;
/// Флаг диапазона `5 ГГц`.
pub const CHAN_5GHZ: u16 = 0x0100;

/// TX-флаг: передача завершилась ошибкой.
pub const TX_FAIL: u16 = 0x0001;
/// TX-флаг: использовать CTS-защиту.
pub const TX_CTS: u16 = 0x0002;
/// TX-флаг: использовать RTS/CTS.
pub const TX_RTS: u16 = 0x0004;
/// TX-флаг: не ждать ACK.
pub const TX_NOACK: u16 = 0x0008;
/// TX-флаг: не перезаписывать sequence number.
pub const TX_NOSEQNO: u16 = 0x0010;

/// Поле `CHANNEL`: частота и флаги.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Channel {
    /// Частота в `МГц`.
    pub frequency: u16,
    /// Биты `IEEE80211_CHAN_*`.
    pub flags: u16,
}

impl Channel {
    /// Создаёт поле канала.
    #[must_use]
    pub const fn new(frequency: u16, flags: u16) -> Self {
        Self { frequency, flags }
    }
}

/// Заголовок radiotap с необязательными полями.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Radiotap {
    /// Скорость в единицах `500 кбит/с`.
    pub rate: Option<u8>,
    /// Канал передачи.
    pub channel: Option<Channel>,
    /// TX-флаги `IEEE80211_RADIOTAP_F_TX_*`.
    pub tx_flags: Option<u16>,
}

impl Radiotap {
    /// Создаёт пустой заголовок.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            rate: None,
            channel: None,
            tx_flags: None,
        }
    }

    /// Задаёт скорость в единицах `500 кбит/с`.
    #[must_use]
    pub const fn with_rate(mut self, rate: u8) -> Self {
        self.rate = Some(rate);
        self
    }

    /// Задаёт канал.
    #[must_use]
    pub const fn with_channel(mut self, frequency: u16, flags: u16) -> Self {
        self.channel = Some(Channel { frequency, flags });
        self
    }

    /// Задаёт канал и вычисляет флаги по частоте.
    #[must_use]
    pub const fn with_frequency(mut self, frequency: u16) -> Self {
        self.channel = Some(Channel {
            frequency,
            flags: channel_flags(frequency),
        });
        self
    }

    /// Задаёт TX-флаги.
    #[must_use]
    pub const fn with_tx_flags(mut self, flags: u16) -> Self {
        self.tx_flags = Some(flags);
        self
    }

    /// Собирает заголовок в байты.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut present = 0u32;
        if self.rate.is_some() {
            present |= RADIOTAP_F_RATE;
        }
        if self.channel.is_some() {
            present |= RADIOTAP_F_CHANNEL;
        }
        if self.tx_flags.is_some() {
            present |= RADIOTAP_F_TX_FLAGS;
        }

        let mut out = Vec::with_capacity(24);
        out.push(RADIOTAP_VERSION);
        out.push(0);
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&present.to_le_bytes());

        if let Some(rate) = self.rate {
            out.push(rate);
        }
        if let Some(channel) = self.channel {
            pad_to(&mut out, 2);
            out.extend_from_slice(&channel.frequency.to_le_bytes());
            out.extend_from_slice(&channel.flags.to_le_bytes());
        }
        if let Some(flags) = self.tx_flags {
            pad_to(&mut out, 2);
            out.extend_from_slice(&flags.to_le_bytes());
        }

        let len = u16::try_from(out.len()).unwrap_or(0);
        if let Some(slot) = out.get_mut(2..4) {
            slot.copy_from_slice(&len.to_le_bytes());
        }
        out
    }

    /// Разбирает заголовок и возвращает его вместе с полной длиной в байтах.
    ///
    /// Неизвестные поля прекращают разбор: заполненные поля остаются
    /// корректными, а длина заголовка всё равно возвращается.
    #[must_use]
    pub fn parse(data: &[u8]) -> Option<(Self, usize)> {
        if data.len() < RADIOTAP_MIN_LEN || data.first().copied()? != RADIOTAP_VERSION {
            return None;
        }
        let len = usize::from(u16::from_le_bytes(data.get(2..4)?.try_into().ok()?));
        if len < RADIOTAP_MIN_LEN || len > data.len() {
            return None;
        }

        let mut present_words = Vec::new();
        let mut offset = 4usize;
        loop {
            let word =
                u32::from_le_bytes(data.get(offset..offset.checked_add(4)?)?.try_into().ok()?);
            present_words.push(word);
            offset = offset.checked_add(4)?;
            if word & (1u32 << 31) == 0 {
                break;
            }
            if present_words.len() > 8 {
                return None;
            }
        }

        let mut header = Self::new();
        let mut cursor = offset;
        'fields: for (word_index, word) in present_words.iter().enumerate() {
            for bit in 0..31usize {
                if word & (1u32 << bit) == 0 {
                    continue;
                }
                let field = word_index.checked_mul(32)?.checked_add(bit)?;
                match field {
                    2 => {
                        header.rate = data.get(cursor).copied();
                        cursor = cursor.checked_add(1)?;
                    }
                    3 => {
                        cursor = align_to(cursor, 2);
                        let end = cursor.checked_add(4)?;
                        let raw = data.get(cursor..end)?;
                        let frequency = u16::from_le_bytes(raw.get(0..2)?.try_into().ok()?);
                        let flags = u16::from_le_bytes(raw.get(2..4)?.try_into().ok()?);
                        header.channel = Some(Channel { frequency, flags });
                        cursor = end;
                    }
                    15 => {
                        cursor = align_to(cursor, 2);
                        let end = cursor.checked_add(2)?;
                        let raw = data.get(cursor..end)?;
                        header.tx_flags = Some(u16::from_le_bytes(raw.try_into().ok()?));
                        cursor = end;
                    }
                    _ => break 'fields,
                }
            }
        }

        Some((header, len))
    }
}

/// Возвращает флаги канала по частоте в `МГц`.
#[must_use]
pub const fn channel_flags(frequency: u16) -> u16 {
    if frequency < 3000 {
        CHAN_2GHZ | CHAN_CCK
    } else {
        CHAN_5GHZ | CHAN_OFDM
    }
}

fn pad_to(out: &mut Vec<u8>, align: usize) {
    while !out.len().is_multiple_of(align) {
        out.push(0);
    }
}

const fn align_to(offset: usize, align: usize) -> usize {
    offset.saturating_add(align - 1) & !(align - 1)
}

#[cfg(test)]
mod tests {
    use super::{
        CHAN_2GHZ, CHAN_5GHZ, CHAN_CCK, RADIOTAP_F_CHANNEL, RADIOTAP_F_RATE, RADIOTAP_F_TX_FLAGS,
        Radiotap, TX_NOACK, channel_flags,
    };

    #[test]
    fn encodes_minimal_header() {
        let raw = Radiotap::new().encode();
        assert_eq!(raw, [0, 0, 8, 0, 0, 0, 0, 0]);
        let (parsed, len) = Radiotap::parse(&raw).unwrap();
        assert_eq!(len, 8);
        assert_eq!(parsed, Radiotap::new());
    }

    #[test]
    fn encodes_rate_and_channel() {
        let header = Radiotap::new()
            .with_rate(2)
            .with_frequency(2437)
            .with_tx_flags(TX_NOACK);
        let raw = header.encode();

        assert_eq!(u16::from_le_bytes([raw[2], raw[3]]), 16);
        let present = u32::from_le_bytes([raw[4], raw[5], raw[6], raw[7]]);
        assert_eq!(
            present,
            RADIOTAP_F_RATE | RADIOTAP_F_CHANNEL | RADIOTAP_F_TX_FLAGS
        );
        assert_eq!(raw[8], 2);

        let (parsed, len) = Radiotap::parse(&raw).unwrap();
        assert_eq!(len, 16);
        assert_eq!(parsed.rate, Some(2));
        let channel = parsed.channel.unwrap();
        assert_eq!(channel.frequency, 2437);
        assert_eq!(channel.flags, channel_flags(2437));
        assert_eq!(parsed.tx_flags, Some(TX_NOACK));
    }

    #[test]
    fn rejects_short_or_inconsistent_headers() {
        assert!(Radiotap::parse(&[]).is_none());
        assert!(Radiotap::parse(&[0, 0, 8, 0, 0, 0, 0]).is_none());
        assert!(Radiotap::parse(&[7, 0, 8, 0, 0, 0, 0, 0]).is_none());
        assert!(Radiotap::parse(&[0, 0, 4, 0, 0, 0, 0, 0]).is_none());
        assert!(Radiotap::parse(&[0, 0, 40, 0, 0, 0, 0, 0]).is_none());
    }

    #[test]
    fn computes_channel_flags() {
        assert_eq!(channel_flags(2412), CHAN_2GHZ | CHAN_CCK);
        assert_eq!(channel_flags(5180), CHAN_5GHZ | super::CHAN_OFDM);
    }
}
