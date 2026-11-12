//! Инъекция 802.11 кадров и управление WLAN.
//!
//! Крейт разделён на два слоя:
//!
//! * [`raw`] — MAC-адреса, radiotap, кадры 802.11, информационные элементы,
//!   `EAPOL`/WPS и `AF_PACKET`-сокет;
//! * [`high`] — команды WLAN: режим интерфейса, канал, сканирование,
//!   подключение к открытой сети, WPS PIN и генерация PIN.
//!
//! Высокоуровневый слой переиспользует [`raw`] для инъекции и
//! `uu-linux-kernel-netlink` для `nl80211`.
//!
//! # Память
//!
//! В крейте нет встроенной базы `OUI`/производителей: такие таблицы весят
//! мегабайты. Объём памяти определяется одним кадром и одним результатом
//! сканирования; для больших эфиров используйте потоковый
//! [`high::Wlan::scan_each`].
//!
//! # Логирование
//!
//! `tracing` — опциональная фича и по умолчанию выключена. Без неё макросы
//! логирования раскрываются в пустоту, а аргументы не вычисляются. Включить:
//!
//! ```toml
//! uu-linux-kernel-wlan = { path = "...", features = ["tracing"] }
//! ```
//!
//! # Пример
//!
//! ```no_run
//! # use uu_linux_kernel_wlan::{Error, Wlan};
//! # fn main() -> Result<(), Error> {
//! let mut wlan = Wlan::open("wlan0")?;
//! wlan.set_monitor()?;
//! wlan.set_channel(6)?;
//!
//! for bss in wlan.scan()? {
//!     println!("{bss}");
//!     for pin in bss.wps_pins() {
//!         println!("  WPS PIN: {pin}");
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! Требуются `root` или `CAP_NET_RAW`/`CAP_NET_ADMIN`.

#[cfg(not(target_os = "linux"))]
compile_error!("uu-linux-kernel-wlan supports Linux only");

#[macro_use]
mod telemetry;

mod crypto;
mod error;

pub mod high;
pub mod raw;

pub use crate::error::{Error, Result};
pub use crate::high::{Bss, Wlan, WpsCredentials, WpsIe};
pub use crate::raw::{MacAddr, PacketSocket, Radiotap};
