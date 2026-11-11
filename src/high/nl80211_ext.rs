//! Константы nl80211, нужные высокоуровневому слою.
//!
//! Значения взяты из `include/uapi/linux/nl80211.h`. В `libc` этих
//! констант нет, поэтому они объявлены здесь локально.

/// `NL80211_CMD_TRIGGER_SCAN`.
pub const CMD_TRIGGER_SCAN: u8 = 33;
/// `NL80211_CMD_GET_SCAN`.
pub const CMD_GET_SCAN: u8 = 32;
/// `NL80211_CMD_CONNECT`.
pub const CMD_CONNECT: u8 = 46;
/// `NL80211_CMD_DISCONNECT`.
pub const CMD_DISCONNECT: u8 = 48;

/// `NL80211_ATTR_IFINDEX`.
pub const ATTR_IFINDEX: u16 = 3;
/// `NL80211_ATTR_SSID`.
pub const ATTR_SSID: u16 = 52;
/// `NL80211_ATTR_SCAN_FREQUENCIES`.
pub const ATTR_SCAN_FREQUENCIES: u16 = 44;
/// `NL80211_ATTR_SCAN_SSIDS`.
pub const ATTR_SCAN_SSIDS: u16 = 45;
/// `NL80211_ATTR_BSS`.
pub const ATTR_BSS: u16 = 47;
/// `NL80211_ATTR_AUTH_TYPE`.
pub const ATTR_AUTH_TYPE: u16 = 53;
/// `NL80211_ATTR_SCAN_FLAGS`.
pub const ATTR_SCAN_FLAGS: u16 = 158;

/// `NL80211_BSS_BSSID`.
pub const BSS_BSSID: u16 = 1;
/// `NL80211_BSS_FREQUENCY`.
pub const BSS_FREQUENCY: u16 = 2;
/// `NL80211_BSS_INFORMATION_ELEMENTS`.
pub const BSS_INFORMATION_ELEMENTS: u16 = 6;
/// `NL80211_BSS_SIGNAL_MBM`.
pub const BSS_SIGNAL_MBM: u16 = 7;
/// `NL80211_BSS_STATUS`.
pub const BSS_STATUS: u16 = 9;
/// `NL80211_BSS_SEEN_MS_AGO`.
pub const BSS_SEEN_MS_AGO: u16 = 10;
/// `NL80211_BSS_BEACON_IES`.
pub const BSS_BEACON_IES: u16 = 11;

/// `NL80211_AUTHTYPE_OPEN_SYSTEM`.
pub const AUTHTYPE_OPEN_SYSTEM: u32 = 0;

/// `NL80211_SCAN_FLAG_FLUSH`.
pub const SCAN_FLAG_FLUSH: u32 = 1;
