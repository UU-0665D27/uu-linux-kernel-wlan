//! Подключается к сети по WPS PIN и печатает полученный PSK.
//!
//! Запуск (нужен root):
//!
//! ```text
//! cargo run --example wps_connect -- wlan0 LP aa:bb:cc:dd:ee:ff 48293563
//! ```

use uu_linux_kernel_wlan::{Error, MacAddr, Wlan};

fn main() -> Result<(), Error> {
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
