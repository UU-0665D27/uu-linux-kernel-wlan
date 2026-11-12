//! Сканирует эфир и печатает сети вместе с WPS PIN-кандидатами.
//!
//! Запуск (нужен root). Уровень логов задаётся только через `RUST_LOG`:
//!
//! ```text
//! cargo run --features tracing --example wlan_scan -- wlan0
//! RUST_LOG=debug cargo run --features tracing --example wlan_scan -- wlan0
//! ```

use uu_linux_kernel_wlan::{Error, Wlan};

fn main() -> Result<(), Error> {
    init_tracing();

    let ifname = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "wlan0".to_string());

    let mut wlan = Wlan::open(&ifname)?;
    println!("scanning on {ifname}");

    for bss in wlan.scan()? {
        println!("{bss}");
        if bss.is_wps() {
            for pin in bss.wps_pins() {
                println!("  WPS PIN: {pin}");
            }
        }
    }
    Ok(())
}

/// Включает логи по `RUST_LOG`, если крейт собран с фичей `tracing`.
#[cfg(feature = "tracing")]
fn init_tracing() {
    use tracing_subscriber::EnvFilter;

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("off"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init();
}

/// Без фичи `tracing` логировать нечего.
#[cfg(not(feature = "tracing"))]
const fn init_tracing() {}
