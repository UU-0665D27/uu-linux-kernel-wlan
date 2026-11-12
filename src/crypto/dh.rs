//! `Diffie-Hellman` group 5 (`RFC 3526`, 1536 бит, генератор 2).
//!
//! Возведение в степень считается по методу Монтгомери над 48 словами
//! `u32`. Вся арифметика на стеке: куча не используется, размер ключа
//! фиксирован.

use core::cmp::Ordering;

use super::random::fill_random;
use crate::{Error, Result};

/// Длина простого модуля и открытого ключа в байтах.
pub const DH_LEN: usize = 192;
/// Длина приватного ключа в байтах.
pub const DH_PRIVATE_LEN: usize = 192;

const LIMBS: usize = DH_LEN / 4;
const WORD_BITS: u32 = 32;
const ROUND_BITS: usize = DH_LEN * 8;

/// Простое число группы 5 (`2^1536 - 2^1472 - 1 + 2^64 * ([2^1406 pi] + 741804)`).
#[rustfmt::skip]
pub const DH_GROUP5_PRIME: [u8; DH_LEN] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc9, 0x0f, 0xda, 0xa2,
    0x21, 0x68, 0xc2, 0x34, 0xc4, 0xc6, 0x62, 0x8b, 0x80, 0xdc, 0x1c, 0xd1,
    0x29, 0x02, 0x4e, 0x08, 0x8a, 0x67, 0xcc, 0x74, 0x02, 0x0b, 0xbe, 0xa6,
    0x3b, 0x13, 0x9b, 0x22, 0x51, 0x4a, 0x08, 0x79, 0x8e, 0x34, 0x04, 0xdd,
    0xef, 0x95, 0x19, 0xb3, 0xcd, 0x3a, 0x43, 0x1b, 0x30, 0x2b, 0x0a, 0x6d,
    0xf2, 0x5f, 0x14, 0x37, 0x4f, 0xe1, 0x35, 0x6d, 0x6d, 0x51, 0xc2, 0x45,
    0xe4, 0x85, 0xb5, 0x76, 0x62, 0x5e, 0x7e, 0xc6, 0xf4, 0x4c, 0x42, 0xe9,
    0xa6, 0x37, 0xed, 0x6b, 0x0b, 0xff, 0x5c, 0xb6, 0xf4, 0x06, 0xb7, 0xed,
    0xee, 0x38, 0x6b, 0xfb, 0x5a, 0x89, 0x9f, 0xa5, 0xae, 0x9f, 0x24, 0x11,
    0x7c, 0x4b, 0x1f, 0xe6, 0x49, 0x28, 0x66, 0x51, 0xec, 0xe4, 0x5b, 0x3d,
    0xc2, 0x00, 0x7c, 0xb8, 0xa1, 0x63, 0xbf, 0x05, 0x98, 0xda, 0x48, 0x36,
    0x1c, 0x55, 0xd3, 0x9a, 0x69, 0x16, 0x3f, 0xa8, 0xfd, 0x24, 0xcf, 0x5f,
    0x83, 0x65, 0x5d, 0x23, 0xdc, 0xa3, 0xad, 0x96, 0x1c, 0x62, 0xf3, 0x56,
    0x20, 0x85, 0x52, 0xbb, 0x9e, 0xd5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6d,
    0x67, 0x0c, 0x35, 0x4e, 0x4a, 0xbc, 0x98, 0x04, 0xf1, 0x74, 0x6c, 0x08,
    0xca, 0x23, 0x73, 0x27, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
];

type Uint = [u32; LIMBS];

fn low(value: u64) -> u32 {
    u32::try_from(value & u64::from(u32::MAX)).unwrap_or(0)
}

fn high(value: u64) -> u32 {
    u32::try_from(value >> WORD_BITS).unwrap_or(0)
}

fn from_be(bytes: &[u8; DH_LEN]) -> Uint {
    let mut limbs = [0u32; LIMBS];
    for (index, chunk) in bytes.as_chunks::<4>().0.iter().enumerate() {
        if let Some(slot) = limbs.get_mut(LIMBS - 1 - index) {
            *slot = u32::from_be_bytes(*chunk);
        }
    }
    limbs
}

fn to_be(limbs: &Uint) -> [u8; DH_LEN] {
    let mut out = [0u8; DH_LEN];
    for (chunk, limb) in out
        .as_chunks_mut::<4>()
        .0
        .iter_mut()
        .zip(limbs.iter().rev())
    {
        chunk.copy_from_slice(&limb.to_be_bytes());
    }
    out
}

fn cmp(left: &Uint, right: &Uint) -> Ordering {
    for (a, b) in left.iter().rev().zip(right.iter().rev()) {
        match a.cmp(b) {
            Ordering::Equal => {}
            other => return other,
        }
    }
    Ordering::Equal
}

fn sub_assign(target: &mut Uint, subtrahend: &Uint) {
    let mut borrow = 0u64;
    for (value, sub) in target.iter_mut().zip(subtrahend.iter()) {
        let left = u64::from(*value);
        let right = u64::from(*sub) + borrow;
        if left >= right {
            *value = low(left - right);
            borrow = 0;
        } else {
            *value = low(left + (1u64 << WORD_BITS) - right);
            borrow = 1;
        }
    }
}

fn n0_inverse(modulus: &Uint) -> u32 {
    let mut inverse = 1u32;
    let first = modulus.first().copied().unwrap_or(1);
    for _ in 0..5 {
        inverse = inverse.wrapping_mul(2u32.wrapping_sub(first.wrapping_mul(inverse)));
    }
    0u32.wrapping_sub(inverse)
}

fn add_carry(workspace: &mut [u32], start: usize, mut carry: u64) {
    let mut index = start;
    while carry != 0 {
        let Some(slot) = workspace.get_mut(index) else {
            break;
        };
        let sum = u64::from(*slot) + carry;
        *slot = low(sum);
        carry = u64::from(high(sum));
        index += 1;
    }
}

fn mont_mul(left: &Uint, right: &Uint, modulus: &Uint, n0: u32) -> Uint {
    const EXTRA: usize = 2 * LIMBS + 2;
    let mut workspace = [0u32; EXTRA];

    for (index, left_limb) in left.iter().enumerate() {
        let mut carry = 0u64;
        for (position, right_limb) in right.iter().enumerate() {
            let Some(slot) = workspace.get_mut(index + position) else {
                break;
            };
            let sum = u64::from(*slot) + u64::from(*left_limb) * u64::from(*right_limb) + carry;
            *slot = low(sum);
            carry = u64::from(high(sum));
        }
        add_carry(&mut workspace, index + LIMBS, carry);
    }

    for index in 0..LIMBS {
        let factor_limb = workspace.get(index).copied().unwrap_or(0);
        let factor = low(u64::from(factor_limb).wrapping_mul(u64::from(n0)));
        let mut carry = 0u64;
        for (position, modulus_limb) in modulus.iter().enumerate() {
            let Some(slot) = workspace.get_mut(index + position) else {
                break;
            };
            let sum = u64::from(*slot) + u64::from(factor) * u64::from(*modulus_limb) + carry;
            *slot = low(sum);
            carry = u64::from(high(sum));
        }
        add_carry(&mut workspace, index + LIMBS, carry);
    }

    let mut result = [0u32; LIMBS];
    for (slot, limb) in result.iter_mut().zip(workspace.iter().skip(LIMBS)) {
        *slot = *limb;
    }
    let extra = workspace.get(2 * LIMBS).copied().unwrap_or(0);
    if extra != 0 || cmp(&result, modulus) != Ordering::Less {
        sub_assign(&mut result, modulus);
    }
    result
}

fn double_mod(value: &mut Uint, modulus: &Uint) {
    let mut carry = 0u32;
    for limb in value.iter_mut() {
        let next = *limb >> 31;
        *limb = (*limb << 1) | carry;
        carry = next;
    }
    if carry != 0 || cmp(value, modulus) != Ordering::Less {
        sub_assign(value, modulus);
    }
}

fn modexp(base: &Uint, exponent: &[u8; DH_LEN], modulus: &Uint, n0: u32) -> Uint {
    let mut one = [0u32; LIMBS];
    if let Some(slot) = one.first_mut() {
        *slot = 1;
    }

    let mut mont_one = one;
    for _ in 0..ROUND_BITS {
        double_mod(&mut mont_one, modulus);
    }
    let mut mont_r2 = mont_one;
    for _ in 0..ROUND_BITS {
        double_mod(&mut mont_r2, modulus);
    }

    let base_mont = mont_mul(base, &mont_r2, modulus, n0);
    let mut accumulator = mont_one;
    for byte in exponent {
        for shift in (0..8).rev() {
            accumulator = mont_mul(&accumulator, &accumulator, modulus, n0);
            if (byte >> shift) & 1 == 1 {
                accumulator = mont_mul(&accumulator, &base_mont, modulus, n0);
            }
        }
    }
    mont_mul(&accumulator, &one, modulus, n0)
}

fn prime() -> Uint {
    from_be(&DH_GROUP5_PRIME)
}

/// Генерирует случайный приватный ключ (192 байта).
///
/// # Errors
///
/// Возвращает [`Error::Io`], если `getrandom(2)` недоступен.
pub fn generate_private_key() -> Result<[u8; DH_PRIVATE_LEN]> {
    let mut key = [0u8; DH_PRIVATE_LEN];
    fill_random(&mut key)?;
    if cmp(&from_be(&key), &prime()) != Ordering::Less {
        key[0] = 0;
    }
    Ok(key)
}

/// Считает открытый ключ `2^private mod p`.
#[must_use]
pub fn public_key(private: &[u8; DH_PRIVATE_LEN]) -> [u8; DH_LEN] {
    let mut base = [0u32; LIMBS];
    if let Some(slot) = base.first_mut() {
        *slot = 2;
    }
    let modulus = prime();
    let n0 = n0_inverse(&modulus);
    to_be(&modexp(&base, private, &modulus, n0))
}

/// Считает общий секрет `peer^private mod p`.
///
/// `peer` может быть короче 192 байт: он дополняется нулями слева.
///
/// # Errors
///
/// Возвращает [`Error::Message`], если открытый ключ пустой, больше модуля
/// или равен 0/1.
pub fn shared_secret(private: &[u8; DH_PRIVATE_LEN], peer: &[u8]) -> Result<[u8; DH_LEN]> {
    if peer.len() > DH_LEN {
        return Err(Error::Message("DH public key is too long".to_string()));
    }
    let mut padded = [0u8; DH_LEN];
    let offset = DH_LEN - peer.len();
    if let Some(slot) = padded.get_mut(offset..) {
        slot.copy_from_slice(peer);
    }

    let peer_key = from_be(&padded);
    let modulus = prime();
    if cmp(&peer_key, &modulus) != Ordering::Less {
        return Err(Error::Message(
            "DH public key is not below modulus".to_string(),
        ));
    }
    if peer_key.iter().all(|limb| *limb == 0) {
        return Err(Error::Message("DH public key is zero".to_string()));
    }
    let mut one = [0u32; LIMBS];
    if let Some(slot) = one.first_mut() {
        *slot = 1;
    }
    if cmp(&peer_key, &one) == Ordering::Equal {
        return Err(Error::Message("DH public key is one".to_string()));
    }

    let n0 = n0_inverse(&modulus);
    Ok(to_be(&modexp(&peer_key, private, &modulus, n0)))
}

#[cfg(test)]
mod tests {
    use super::{
        DH_GROUP5_PRIME, DH_LEN, from_be, generate_private_key, prime, public_key, shared_secret,
        to_be,
    };

    fn with_exponent(value: u8) -> [u8; DH_LEN] {
        let mut key = [0u8; DH_LEN];
        if let Some(last) = key.last_mut() {
            *last = value;
        }
        key
    }

    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            let _ = write!(out, "{byte:02x}");
        }
        out
    }

    #[test]
    fn prime_roundtrip() {
        assert_eq!(to_be(&from_be(&DH_GROUP5_PRIME)), DH_GROUP5_PRIME);
    }

    fn small(value: u16) -> [u8; DH_LEN] {
        let mut key = [0u8; DH_LEN];
        let bytes = value.to_be_bytes();
        if let Some(slot) = key.get_mut(DH_LEN - bytes.len()..) {
            slot.copy_from_slice(&bytes);
        }
        key
    }

    #[test]
    fn computes_small_powers() {
        assert_eq!(public_key(&with_exponent(2)), small(4));
        assert_eq!(public_key(&with_exponent(3)), small(8));
        assert_eq!(public_key(&with_exponent(10)), small(1024));
    }

    #[test]
    fn shared_secrets_match() {
        let alice = with_exponent(2);
        let bob = with_exponent(3);
        let alice_public = public_key(&alice);
        let bob_public = public_key(&bob);
        let from_alice = shared_secret(&alice, &bob_public).unwrap();
        let from_bob = shared_secret(&bob, &alice_public).unwrap();
        assert_eq!(from_alice, from_bob);
        assert_eq!(from_alice, public_key(&with_exponent(6)));
    }

    #[test]
    fn matches_reference_modexp() {
        let mut exponent = [0u8; DH_LEN];
        for (index, byte) in exponent.iter_mut().enumerate() {
            *byte = u8::try_from(index).unwrap_or(0);
        }
        let expected = "ca831509b0009fd2f753a17555ec5fd6b5ac81ba602587dfce0413de4be654e6\
                        f6af6059f1ed06598d586a37726ea0a9f15a7ceba7779f02796ed7934d1786c0\
                        7f51002f9246bb94adccdea686a33d1d7e86c6959f76adb186bdd30e748b430dd\
                        9397aad0606238344326682307462372dab942410bc073a47c3cca8ef619ed68\
                        1ba05ac5dd3fc0c5d3f3f8e0f7b34bf46f0335563330f2a5fb35eb7206769c36ad\
                        66ec348820047cba414611962cee493e724ad549642d36d70264375cb238e";
        let expected: String = expected.chars().filter(|ch| !ch.is_whitespace()).collect();
        assert_eq!(hex(&public_key(&exponent)), expected);
        assert_eq!(expected.len(), DH_LEN * 2);
    }

    #[test]
    fn rejects_invalid_peer_keys() {
        let private = with_exponent(5);
        assert!(shared_secret(&private, &[]).is_err());
        assert!(shared_secret(&private, &[1]).is_err());
        assert!(shared_secret(&private, &[0; DH_LEN + 1]).is_err());
        assert!(shared_secret(&private, &DH_GROUP5_PRIME).is_err());
    }

    #[test]
    fn generates_private_keys_below_modulus() {
        let key = generate_private_key().unwrap();
        assert_eq!(
            super::cmp(&from_be(&key), &prime()),
            core::cmp::Ordering::Less
        );
    }
}
