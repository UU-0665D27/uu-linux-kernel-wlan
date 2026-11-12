//! Низкоуровневый слой: MAC, radiotap, кадры 802.11, IE, EAPOL/WPS и сокет.
//!
//! Модуль работает с байтами напрямую и не держит глобальных таблиц, чтобы
//! помещаться на устройствах с малым объёмом памяти.

pub mod eapol;
pub mod frame;
pub mod ie;
pub mod mac;
pub mod radiotap;
pub mod socket;

pub use eapol::{
    Eap, EapExpanded, Eapol, WpsTlv, WpsTlvIter, WpsTlvWriter, eap_expanded, eap_identity, eapol,
    find_tlv, wps_eap,
};
pub use frame::{
    FrameControl, MgmtHeader, auth_open, beacon, data_frame, deauthenticate, disassociate,
    eapol_data, eapol_from_ap, eapol_to_ap, is_eapol, parse_frame_control, probe_request,
    probe_response,
};
pub use ie::{IE_SSID, IE_VENDOR, Ie, IeIter, IeList, find, find_wps};
pub use mac::MacAddr;
pub use radiotap::{Channel, RADIOTAP_MIN_LEN, Radiotap, channel_flags};
pub use socket::PacketSocket;
