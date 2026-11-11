//! Сканирует эфир и печатает сети вместе с WPS PIN-кандидатами.
//!
//! Запуск (нужен root):
//!
//! ```text
//! cargo run --example wlan_scan -- wlan0
//! ```

use uu_linux_kernel_wlan::{Error, Wlan};

fn main() -> Result<(), Error> {
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
