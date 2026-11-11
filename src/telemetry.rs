//! Макросы логирования.
//!
//! При выключенной фиче `tracing` аргументы макросов не вычисляются и код
//! логирования полностью исчезает из сборки.

#[cfg(feature = "tracing")]
macro_rules! trace {
    ($($arg:tt)*) => {
        tracing::trace!($($arg)*)
    };
}

#[cfg(not(feature = "tracing"))]
macro_rules! trace {
    ($($arg:tt)*) => {};
}
