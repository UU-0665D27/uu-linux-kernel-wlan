//! Печатает radiotap-параметры и первые байты принятых кадров.
//!
//! Запуск (нужен root и monitor-режим):
//!
//! ```text
//! cargo run --example raw_sniff -- wlan0
//! ```

use uu_linux_kernel_wlan::raw::Radiotap;
use uu_linux_kernel_wlan::{Error, PacketSocket};

fn main() -> Result<(), Error> {
    let ifname = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "wlan0".to_string());
    let socket = PacketSocket::open(&ifname)?;
    println!("sniffing on {ifname}");

    loop {
        let data = socket.recv()?;
        let Some((radiotap, header_len)) = Radiotap::parse(&data) else {
            println!("{} bytes (no radiotap)", data.len());
            continue;
        };
        let frame = data.get(header_len..).unwrap_or(&[]);
        let control = frame.get(..2).unwrap_or(&[]);
        println!(
            "{} bytes  rate={:?}  channel={:?}  fc={control:02x?}",
            data.len(),
            radiotap.rate,
            radiotap.channel,
        );
    }
}
