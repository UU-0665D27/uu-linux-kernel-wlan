//! Источник случайных чисел.
//!
//! Используется `getrandom(2)`: он не требует файловых дескрипторов и
//! доступен на всех поддерживаемых ядрах Linux.

use crate::{Error, Result};

/// Заполняет буфер случайными байтами.
///
/// # Errors
///
/// Возвращает [`Error::Io`], если системный вызов завершился ошибкой.
pub fn fill_random(buffer: &mut [u8]) -> Result<()> {
    let mut filled = 0usize;
    while filled < buffer.len() {
        let Some(rest) = buffer.get_mut(filled..) else {
            break;
        };
        // SAFETY: указатель и длина взяты из живого среза `rest`.
        let written = unsafe {
            libc::syscall(
                libc::SYS_getrandom,
                rest.as_mut_ptr().cast::<libc::c_void>(),
                rest.len(),
                0u32,
            )
        };
        if written < 0 {
            return Err(Error::Io(std::io::Error::last_os_error()));
        }
        let written = usize::try_from(written).unwrap_or(0);
        if written == 0 {
            return Err(Error::Io(std::io::Error::from(
                std::io::ErrorKind::UnexpectedEof,
            )));
        }
        filled += written;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::fill_random;

    #[test]
    fn fills_buffer() {
        let mut first = [0u8; 32];
        let mut second = [0u8; 32];
        fill_random(&mut first).unwrap();
        fill_random(&mut second).unwrap();
        assert_ne!(first, [0u8; 32]);
        assert_ne!(first, second);
    }
}
