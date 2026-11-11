//! Ошибки библиотеки.

use std::io;

/// Ошибки низкоуровневого и высокоуровневого слоёв.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Ошибка ввода-вывода (`socket`, `sendto`, `recvfrom`, `fcntl`).
    #[error("io: {0}")]
    Io(#[from] io::Error),

    /// Ошибка netlink/nl80211.
    #[error("netlink: {0}")]
    Netlink(#[from] uu_linux_kernel_netlink::Error),

    /// Некорректный MAC-адрес.
    #[error("invalid MAC address: {0}")]
    Mac(String),

    /// Пакет обрезан или имеет неверный формат.
    #[error("malformed packet")]
    Malformed,

    /// Интерфейс с таким именем не найден.
    #[error("interface '{0}' not found")]
    InterfaceNotFound(String),

    /// Значение не помещается в поле протокола.
    #[error("value out of range: {0}")]
    OutOfRange(i64),

    /// Операция требует `root` или `CAP_NET_RAW`/`CAP_NET_ADMIN`.
    #[error("operation requires root or CAP_NET_RAW/CAP_NET_ADMIN")]
    PermissionDenied,

    /// Прочая ошибка с текстовым описанием.
    #[error("{0}")]
    Message(String),
}

/// Результат операций библиотеки.
pub type Result<T> = std::result::Result<T, Error>;
