//! Подключается к сети по WPS PIN и печатает полученный PSK.
//!
//! Запуск (нужен root). Уровень логов задаётся только через `RUST_LOG`:
//!
//! ```text
//! cargo run --features tracing --example wps_connect -- wlan0 LP aa:bb:cc:dd:ee:ff 48293563
//! RUST_LOG=debug cargo run --features tracing --example wps_connect -- wlan0 LP aa:bb:cc:dd:ee:ff 48293563
//! ```

use uu_linux_kernel_wlan::{Error, MacAddr, Wlan};

fn main() -> Result<(), Error> {
    init_tracing();

    let mut args = std::env::args().skip(1);
    let ifname = args.next().unwrap_or_else(|| "wlan0".to_string());
    let ssid = args.next().unwrap_or_else(|| "LP".to_string());
    let bssid: MacAddr = args.next().unwrap_or_default().parse()?;
    let pin = args.next().unwrap_or_default();

    let mut wlan = Wlan::open(&ifname)?;
    println!("WPS PIN connection to {ssid} ({bssid}) on {ifname}");

    let credentials = wlan.wps_pin_psk(ssid.as_bytes(), bssid, &pin)?;
    println!("SSID: {}", String::from_utf8_lossy(&credentials.ssid));
    println!("PSK:  {}", credentials.psk());
    println!("auth: {:#06x}", credentials.auth_type);
    println!("encr: {:#06x}", credentials.encryption_type);
    if let Some(mac) = credentials.mac_addr {
        println!("mac:  {mac}");
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
