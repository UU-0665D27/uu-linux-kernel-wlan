//! `HMAC-SHA-256` (RFC 2104).

use super::sha256::{Sha256, sha256};

const BLOCK_LEN: usize = 64;
const DIGEST_LEN: usize = 32;

const INNER_PAD: u8 = 0x36;
const OUTER_PAD: u8 = 0x5c;

/// Считает `HMAC-SHA-256` от конкатенации `parts`.
///
/// Разбиение на части нужно, чтобы не собирать буфер в памяти: WPS считает
/// `HMAC` от заголовка и тела отдельно.
#[must_use]
pub fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> [u8; DIGEST_LEN] {
    let mut block = [0u8; BLOCK_LEN];
    if key.len() > BLOCK_LEN {
        let digest = sha256(key);
        if let Some(slot) = block.get_mut(..digest.len()) {
            slot.copy_from_slice(&digest);
        }
    } else if let Some(slot) = block.get_mut(..key.len()) {
        slot.copy_from_slice(key);
    }

    let mut inner = Sha256::new();
    let mut outer = Sha256::new();
    let mut inner_pad = [0u8; BLOCK_LEN];
    let mut outer_pad = [0u8; BLOCK_LEN];
    for ((inner_byte, outer_byte), key_byte) in inner_pad
        .iter_mut()
        .zip(outer_pad.iter_mut())
        .zip(block.iter())
    {
        *inner_byte = key_byte ^ INNER_PAD;
        *outer_byte = key_byte ^ OUTER_PAD;
    }
    inner.update(&inner_pad);
    outer.update(&outer_pad);

    for part in parts {
        inner.update(part);
    }
    let digest = inner.finish();
    outer.update(&digest);
    outer.finish()
}

#[cfg(test)]
mod tests {
    use super::hmac_sha256;

    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            let _ = write!(out, "{byte:02x}");
        }
        out
    }

    #[test]
    fn matches_rfc4231_case_1() {
        let key = [0x0bu8; 20];
        let mac = hmac_sha256(&key, &[b"Hi There"]);
        assert_eq!(
            hex(&mac),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn matches_rfc4231_case_3() {
        let key = [0xaau8; 20];
        let mac = hmac_sha256(&key, &[[0xddu8; 50].as_slice()]);
        assert_eq!(
            hex(&mac),
            "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"
        );
    }

    #[test]
    fn splits_parts_without_changing_digest() {
        let key = b"secret";
        let whole = hmac_sha256(key, &[b"header-body"]);
        let split = hmac_sha256(key, &[b"header", b"", b"-body"]);
        assert_eq!(whole, split);
    }

    #[test]
    fn hashes_long_keys() {
        let key = vec![0x5au8; 100];
        let mac = hmac_sha256(&key, &[b"data"]);
        assert_eq!(mac.len(), 32);
    }
}
