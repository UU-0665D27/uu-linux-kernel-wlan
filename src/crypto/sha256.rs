//! `SHA-256` по FIPS 180-4.
//!
//! Реализация без внешних зависимостей: состояние — 8 слов, буфер — один
//! блок. Память не растёт вместе с объёмом данных.

const BLOCK_LEN: usize = 64;
const DIGEST_LEN: usize = 32;
const ROUNDS: usize = 64;

const INITIAL: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

#[rustfmt::skip]
const K: [u32; ROUNDS] = [
    0x428a_2f98, 0x7137_4491, 0xb5c0_fbcf, 0xe9b5_dba5, 0x3956_c25b, 0x59f1_11f1,
    0x923f_82a4, 0xab1c_5ed5, 0xd807_aa98, 0x1283_5b01, 0x2431_85be, 0x550c_7dc3,
    0x72be_5d74, 0x80de_b1fe, 0x9bdc_06a7, 0xc19b_f174, 0xe49b_69c1, 0xefbe_4786,
    0x0fc1_9dc6, 0x240c_a1cc, 0x2de9_2c6f, 0x4a74_84aa, 0x5cb0_a9dc, 0x76f9_88da,
    0x983e_5152, 0xa831_c66d, 0xb003_27c8, 0xbf59_7fc7, 0xc6e0_0bf3, 0xd5a7_9147,
    0x06ca_6351, 0x1429_2967, 0x27b7_0a85, 0x2e1b_2138, 0x4d2c_6dfc, 0x5338_0d13,
    0x650a_7354, 0x766a_0abb, 0x81c2_c92e, 0x9272_2c85, 0xa2bf_e8a1, 0xa81a_664b,
    0xc24b_8b70, 0xc76c_51a3, 0xd192_e819, 0xd699_0624, 0xf40e_3585, 0x106a_a070,
    0x19a4_c116, 0x1e37_6c08, 0x2748_774c, 0x34b0_bcb5, 0x391c_0cb3, 0x4ed8_aa4a,
    0x5b9c_ca4f, 0x682e_6ff3, 0x748f_82ee, 0x78a5_636f, 0x84c8_7814, 0x8cc7_0208,
    0x90be_fffa, 0xa450_6ceb, 0xbef9_a3f7, 0xc671_78f2,
];

/// Потоковый `SHA-256`.
#[derive(Debug, Clone)]
pub struct Sha256 {
    state: [u32; 8],
    buffer: [u8; BLOCK_LEN],
    buffered: usize,
    length: u64,
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256 {
    /// Создаёт новый контекст.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: INITIAL,
            buffer: [0; BLOCK_LEN],
            buffered: 0,
            length: 0,
        }
    }

    /// Добавляет данные к хешу.
    pub fn update(&mut self, data: &[u8]) {
        self.length = self
            .length
            .wrapping_add(u64::try_from(data.len()).unwrap_or(u64::MAX));

        let mut rest = data;
        if self.buffered > 0 {
            let needed = BLOCK_LEN - self.buffered;
            let take = needed.min(rest.len());
            let (head, tail) = rest.split_at(take);
            let end = self.buffered + take;
            if let Some(slot) = self.buffer.get_mut(self.buffered..end) {
                slot.copy_from_slice(head);
            }
            self.buffered = end;
            rest = tail;
            if self.buffered == BLOCK_LEN {
                compress(&mut self.state, &self.buffer);
                self.buffered = 0;
            }
        }

        while rest.len() >= BLOCK_LEN {
            let (block, tail) = rest.split_at(BLOCK_LEN);
            if let Ok(block) = <[u8; BLOCK_LEN]>::try_from(block) {
                compress(&mut self.state, &block);
            }
            rest = tail;
        }

        if !rest.is_empty() {
            let end = rest.len();
            if let Some(slot) = self.buffer.get_mut(..end) {
                slot.copy_from_slice(rest);
            }
            self.buffered = end;
        }
    }

    /// Завершает вычисление и возвращает дайджест.
    #[must_use]
    pub fn finish(mut self) -> [u8; DIGEST_LEN] {
        let bits = self.length.wrapping_mul(8);
        self.update(&[0x80]);
        while self.buffered != BLOCK_LEN - 8 {
            self.update(&[0]);
        }
        self.update(&bits.to_be_bytes());

        let mut digest = [0u8; DIGEST_LEN];
        for (chunk, word) in digest
            .as_chunks_mut::<4>()
            .0
            .iter_mut()
            .zip(self.state.iter())
        {
            chunk.copy_from_slice(&word.to_be_bytes());
        }
        digest
    }
}

/// Считает `SHA-256` от среза.
#[must_use]
pub fn sha256(data: &[u8]) -> [u8; DIGEST_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finish()
}

fn compress(state: &mut [u32; 8], block: &[u8; BLOCK_LEN]) {
    let mut schedule = [0u32; ROUNDS];
    for (slot, chunk) in schedule.iter_mut().zip(block.as_chunks::<4>().0) {
        *slot = u32::from_be_bytes(*chunk);
    }

    let mut index = 16;
    while index < ROUNDS {
        let s0 = schedule[index - 15].rotate_right(7)
            ^ schedule[index - 15].rotate_right(18)
            ^ (schedule[index - 15] >> 3);
        let s1 = schedule[index - 2].rotate_right(17)
            ^ schedule[index - 2].rotate_right(19)
            ^ (schedule[index - 2] >> 10);
        schedule[index] = schedule[index - 16]
            .wrapping_add(s0)
            .wrapping_add(schedule[index - 7])
            .wrapping_add(s1);
        index += 1;
    }

    let mut h0 = state[0];
    let mut h1 = state[1];
    let mut h2 = state[2];
    let mut h3 = state[3];
    let mut h4 = state[4];
    let mut h5 = state[5];
    let mut h6 = state[6];
    let mut h7 = state[7];

    for (index, constant) in K.iter().enumerate() {
        let s1 = h4.rotate_right(6) ^ h4.rotate_right(11) ^ h4.rotate_right(25);
        let ch = (h4 & h5) ^ (!h4 & h6);
        let temp1 = h7
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(*constant)
            .wrapping_add(schedule.get(index).copied().unwrap_or(0));
        let s0 = h0.rotate_right(2) ^ h0.rotate_right(13) ^ h0.rotate_right(22);
        let maj = (h0 & h1) ^ (h0 & h2) ^ (h1 & h2);
        let temp2 = s0.wrapping_add(maj);

        h7 = h6;
        h6 = h5;
        h5 = h4;
        h4 = h3.wrapping_add(temp1);
        h3 = h2;
        h2 = h1;
        h1 = h0;
        h0 = temp1.wrapping_add(temp2);
    }

    state[0] = state[0].wrapping_add(h0);
    state[1] = state[1].wrapping_add(h1);
    state[2] = state[2].wrapping_add(h2);
    state[3] = state[3].wrapping_add(h3);
    state[4] = state[4].wrapping_add(h4);
    state[5] = state[5].wrapping_add(h5);
    state[6] = state[6].wrapping_add(h6);
    state[7] = state[7].wrapping_add(h7);
}

#[cfg(test)]
mod tests {
    use super::{Sha256, sha256};

    #[test]
    fn hashes_empty_input() {
        assert_eq!(
            sha256(b""),
            [
                0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
                0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
                0x78, 0x52, 0xb8, 0x55,
            ]
        );
    }

    #[test]
    fn hashes_abc() {
        assert_eq!(
            sha256(b"abc"),
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad,
            ]
        );
    }

    #[test]
    fn matches_across_chunk_boundaries() {
        let data = vec![0x61u8; 1000];
        let whole = sha256(&data);

        let mut hasher = Sha256::new();
        for chunk in data.chunks(7) {
            hasher.update(chunk);
        }
        assert_eq!(hasher.finish(), whole);
    }

    #[test]
    fn hashes_long_input() {
        let data = vec![0xa5u8; 1000];
        assert_eq!(sha256(&data)[..4], [0x30, 0xc6, 0x23, 0xea][..4],);
    }
}
