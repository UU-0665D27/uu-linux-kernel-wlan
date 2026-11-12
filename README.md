# uu-linux-kernel-wlan

Инъекция 802.11 кадров и управление WLAN через `nl80211`.

Крейт состоит из двух слоёв:

| Слой | Модуль | Назначение |
| --- | --- | --- |
| `raw` | [`raw`] | MAC, radiotap, кадры 802.11, IE, EAPOL/WPS, `AF_PACKET` |
| `high` | [`high`] | режим интерфейса, канал, сканирование, подключение, WPS PIN |

`high` переиспользует `raw` для инъекции и `uu-linux-kernel-netlink` для
команд `nl80211`.

## Подключение

```toml
[dependencies]
uu-linux-kernel-wlan = { git = "https://github.com/UU-0665D27/uu-linux-kernel-wlan", branch = "main" }
```

Логирование включается фичей: `features = ["tracing"]`.

## Требования

- Linux;
- `root` или `CAP_NET_RAW`/`CAP_NET_ADMIN`;
- драйвер с поддержкой monitor-режима для инъекции.

## Память

В крейте **нет встроенной базы `OUI`/производителей**. Базы MAC-адресов
(например, с `macadress.com`) занимают мегабайты и не подходят для устройств
с 4 МБ памяти. Поэтому:

- `MacAddr` — это ровно 6 байт, без кучи;
- нет глобальных таблиц, кэшей и ленивых статических данных;
- разбор radiotap/IE/EAPOL работает по срезу и не копирует лишнего;
- `Wlan::scan_each()` отдаёт сети по одной через callback, не собирая их в
  `Vec`;
- генерация WPS PIN использует только короткие списки префиксов из
  `uu-wlan-wps-pin-gen`.

Если нужен производитель по MAC, его следует подключать снаружи
(например, компактным индексом на флеше), а не тащить таблицу в бинарник.

## Логирование

`tracing` — опциональная фича и по умолчанию выключена, поэтому зависимость
не компилируется и не попадает в бинарник:

```toml
uu-linux-kernel-wlan = { path = "...", features = ["tracing"] }
```

Без фичи макросы логирования раскрываются в пустоту, а их аргументы не
вычисляются.

## Пример: сканирование и WPS PIN

```rust
use uu_linux_kernel_wlan::{Error, Wlan};

fn main() -> Result<(), Error> {
    let mut wlan = Wlan::open("wlan0")?;

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
```

Потоковый вариант без накопления результата:

```rust
use uu_linux_kernel_wlan::{Error, Wlan};

fn main() -> Result<(), Error> {
    let mut wlan = Wlan::open("wlan0")?;
    wlan.scan_each(|bss| {
        println!("{bss}");
    })?;
    Ok(())
}
```

## Пример: подключение по WPS PIN

```rust
use uu_linux_kernel_wlan::{Error, MacAddr, Wlan};

fn main() -> Result<(), Error> {
    let mut wlan = Wlan::open("wlan0")?;
    let bssid: MacAddr = "aa:bb:cc:dd:ee:ff".parse()?;

    let credentials = wlan.wps_pin_psk(b"LP", bssid, "48293563")?;
    println!("SSID: {}", String::from_utf8_lossy(&credentials.ssid));
    println!("PSK:  {}", credentials.psk());
    Ok(())
}
```

Интерфейс переключается в managed-режим, подключается к `BSSID` с
WPS-элементом `Request Type = Enrollee` и проходит обмен `M1`–`M8` через
EAP-WSC (`EAP-Expanded`, vendor `00:37:2a`). Из `M8` извлекаются `SSID`,
`Network Key` и типы безопасности; сохранение конфигурации остаётся
вызывающему коду.

## Пример: инъекция

```rust
use uu_linux_kernel_wlan::raw::{MacAddr, frame};
use uu_linux_kernel_wlan::{Error, Wlan};

fn main() -> Result<(), Error> {
    let mut wlan = Wlan::open("wlan0")?;
    wlan.set_monitor()?;
    wlan.set_channel(6)?;

    let bssid: MacAddr = "aa:bb:cc:dd:ee:ff".parse()?;
    let deauth = frame::deauthenticate(bssid, MacAddr::BROADCAST, frame::REASON_CLASS3_FRAME);
    wlan.send_frame(&deauth)?;
    Ok(())
}
```

Или напрямую через сокет:

```rust
use uu_linux_kernel_wlan::{Error, PacketSocket, Radiotap};

fn main() -> Result<(), Error> {
    let socket = PacketSocket::open("wlan0")?;
    let radiotap = Radiotap::new().with_frequency(2437).with_tx_flags(uu_linux_kernel_wlan::raw::radiotap::TX_NOACK);
    socket.send_radiotap(&radiotap.encode(), &[])?;
    Ok(())
}
```

Примеры:

```bash
cargo run --example wlan_scan -- wlan0
cargo run --example wps_connect -- wlan0 LP aa:bb:cc:dd:ee:ff 48293563
cargo run --example raw_deauth -- wlan0 aa:bb:cc:dd:ee:ff 6
cargo run --example raw_sniff -- wlan0
```

## Cлой `raw`

- `MacAddr` — разбор/формат `aa:bb:cc:dd:ee:ff`, broadcast/multicast.
- `Radiotap` — поля `RATE`, `CHANNEL`, `TX_FLAGS`, little-endian.
- `frame` — `deauthenticate`, `disassociate`, `probe_request`, `beacon`,
  `probe_response`, `auth_open`, `action`, `data_frame`, `eapol_from_ap`,
  `eapol_to_ap`.
- `ie::IeList`/`IeIter` — сборка и разбор информационных элементов.
- `eapol` — `EAPOL`, `EAP-Expanded`, WPS TLV (big-endian).
- `PacketSocket` — `AF_PACKET`/`SOCK_RAW`, `send`, `recv`, таймауты,
  неблокирующий режим.

## Cлой `high`

- `Wlan::open` — интерфейс + `nl80211` + сокет;
- `set_monitor`/`set_managed`, `set_channel`, `set_frequency`;
- `scan`/`scan_with`/`scan_each`/`scan_each_with`;
- `connect_open`/`disconnect` (только открытые сети);
- `wps_pin_psk` — подключение по WPS PIN и извлечение PSK;
- `WpsIe` — разбор WPS-элемента beacon;
- `Bss::wps_pins`/`wps_app_pins` — PIN по `BSSID`.

WPA2/WPA3 4-way handshake в крейт не входит: для защищённых сетей нужен
userspace-supplicant. WPS state machine (`M1`–`M8`) реализована в
`high::wps_enrollee` и проверяется unit-тестом с офлайн-регистратором.

## Лицензия

MIT OR Apache-2.0.
