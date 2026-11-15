// SPDX-License-Identifier: MIT

//! Deterministic, in-workspace byte-stream fuzzing engine.
//!
//! Parser crates invoke [`run_fuzz`] in their standard `tests/fuzz.rs` suite so
//! every pull request compiles the fuzz targets on stable Rust and executes a
//! deterministic corpus-and-mutation pass under `cargo nextest`. The same
//! targets expose an `#[ignore]` soak entry point calling [`run_fuzz_soak`] for
//! deep scheduled campaigns (`--profile soak --run-ignored ignored-only`).

const PR_ITERATIONS: usize = 4_096;
const SOAK_ITERATIONS: usize = 131_072;
const MAX_MUTATED_LEN: usize = 2_048;

const BOUNDARY_BYTES: [u8; 16] = [
    0x00, 0x01, 0x0a, 0x0d, 0x1e, 0x1f, 0x20, 0x3a, 0x3f, 0x40, 0x54, 0x7f, 0x80, 0xc0, 0xfe, 0xff,
];

const INTERESTING_CHUNKS: [&[u8]; 10] = [
    b"\r\n",
    b"\r\n\r\n",
    &[0x00, 0x00, 0x00, 0x00],
    &[0xff, 0xff, 0xff, 0xff],
    &[0x40, 0x41],
    &[0x80, 0x00, 0x00, 0x01],
    &[0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01],
    &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
    b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n",
    b":method\x00:scheme\x00:authority\x00:path\x00",
];

#[derive(Clone)]
struct Rng {
    state: [u64; 4],
}

impl Rng {
    fn new(seed: u64) -> Self {
        let mut sm = seed;
        let mut next_sm = || {
            sm = sm.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = sm;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^ (z >> 31)
        };
        Self {
            state: [next_sm(), next_sm(), next_sm(), next_sm()],
        }
    }

    fn next_u64(&mut self) -> u64 {
        let result = (self.state[1].wrapping_mul(5))
            .rotate_left(7)
            .wrapping_mul(9);
        let t = self.state[1] << 17;
        self.state[2] ^= self.state[0];
        self.state[3] ^= self.state[1];
        self.state[1] ^= self.state[2];
        self.state[0] ^= self.state[3];
        self.state[2] ^= t;
        self.state[3] = self.state[3].rotate_left(45);
        result
    }

    fn next_u8(&mut self) -> u8 {
        (self.next_u64() & 0xff) as u8
    }

    fn choose_index(&mut self, len: usize) -> usize {
        if len <= 1 {
            0
        } else {
            (self.next_u64() as usize) % len
        }
    }
}

/// Execute a deterministic corpus, truncation, and mutation pass suitable for
/// every PR test run.
pub fn run_fuzz(seeds: &[&[u8]], target: impl FnMut(&[u8])) {
    run_campaign(seeds, PR_ITERATIONS, 0x6e65_7475_6e65_3031, target);
}

/// Execute a deep mutation campaign for scheduled `--profile soak` runs.
pub fn run_fuzz_soak(seeds: &[&[u8]], target: impl FnMut(&[u8])) {
    run_campaign(seeds, SOAK_ITERATIONS, 0x736f_616b_6675_7a7a, target);
}

fn run_campaign(seeds: &[&[u8]], iterations: usize, seed_key: u64, mut target: impl FnMut(&[u8])) {
    target(&[]);
    for &byte in &BOUNDARY_BYTES {
        target(&[byte]);
        target(&[byte, byte]);
    }

    for &seed in seeds {
        target(seed);
        // Every prefix and suffix truncation exercises incomplete-frame and
        // varint boundary paths deterministically.
        let step = (seed.len() / 64).max(1);
        let mut end = 0;
        while end < seed.len() {
            target(&seed[..end]);
            end += step;
        }
        let mut start = 1;
        while start < seed.len() {
            target(&seed[start..]);
            start += step;
        }
    }

    let mut rng = Rng::new(seed_key ^ (seeds.len() as u64));
    let mut buf = Vec::with_capacity(MAX_MUTATED_LEN);

    for step in 0..iterations {
        buf.clear();
        if !seeds.is_empty() && (step % 5 != 0) {
            let base = seeds[rng.choose_index(seeds.len())];
            buf.extend_from_slice(base);
        } else {
            let len = rng.choose_index(256) + 1;
            for _ in 0..len {
                if rng.choose_index(4) == 0 {
                    buf.push(BOUNDARY_BYTES[rng.choose_index(BOUNDARY_BYTES.len())]);
                } else {
                    buf.push(rng.next_u8());
                }
            }
        }

        let mutations = rng.choose_index(6) + 1;
        for _ in 0..mutations {
            mutate(&mut rng, seeds, &mut buf);
        }
        if buf.len() > MAX_MUTATED_LEN {
            buf.truncate(MAX_MUTATED_LEN);
        }
        target(&buf);
    }
}

fn mutate(rng: &mut Rng, seeds: &[&[u8]], buf: &mut Vec<u8>) {
    match rng.choose_index(8) {
        // 0: flip a single bit.
        0 if !buf.is_empty() => {
            let idx = rng.choose_index(buf.len());
            let bit = 1u8 << rng.choose_index(8);
            buf[idx] ^= bit;
        }
        // 1: overwrite with an interesting boundary byte.
        1 if !buf.is_empty() => {
            let idx = rng.choose_index(buf.len());
            buf[idx] = BOUNDARY_BYTES[rng.choose_index(BOUNDARY_BYTES.len())];
        }
        // 2: small arithmetic delta on 1..=4 bytes.
        2 if !buf.is_empty() => {
            let idx = rng.choose_index(buf.len());
            let delta = (rng.choose_index(32) as u8).wrapping_add(1);
            if rng.choose_index(2) == 0 {
                buf[idx] = buf[idx].wrapping_add(delta);
            } else {
                buf[idx] = buf[idx].wrapping_sub(delta);
            }
        }
        // 3: delete a slice.
        3 if buf.len() > 1 => {
            let start = rng.choose_index(buf.len());
            let max_remove = (buf.len() - start).min(32);
            let remove = rng.choose_index(max_remove) + 1;
            buf.drain(start..start + remove);
        }
        // 4: insert an interesting protocol token or boundary chunk.
        4 if buf.len() < MAX_MUTATED_LEN => {
            let chunk = INTERESTING_CHUNKS[rng.choose_index(INTERESTING_CHUNKS.len())];
            let pos = rng.choose_index(buf.len() + 1);
            buf.splice(pos..pos, chunk.iter().copied());
        }
        // 5: duplicate a sub-slice inside the buffer.
        5 if !buf.is_empty() && buf.len() < MAX_MUTATED_LEN => {
            let start = rng.choose_index(buf.len());
            let len = (rng.choose_index((buf.len() - start).min(24)) + 1).min(buf.len() - start);
            let slice = buf[start..start + len].to_vec();
            let pos = rng.choose_index(buf.len() + 1);
            buf.splice(pos..pos, slice);
        }
        // 6: cross-over splice with another seed.
        6 if !seeds.is_empty() && buf.len() < MAX_MUTATED_LEN => {
            let other = seeds[rng.choose_index(seeds.len())];
            if !other.is_empty() {
                let start = rng.choose_index(other.len());
                let end = start + rng.choose_index(other.len() - start) + 1;
                let pos = rng.choose_index(buf.len() + 1);
                buf.splice(pos..pos, other[start..end].iter().copied());
            }
        }
        // 7: append random bytes.
        _ if buf.len() < MAX_MUTATED_LEN => {
            let count = rng.choose_index(16) + 1;
            for _ in 0..count {
                buf.push(rng.next_u8());
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fuzz_campaign_is_deterministic_and_exercises_truncations() {
        let seeds: &[&[u8]] = &[b"ABCD", &[0x40, 0x41, 0x00, 0x04]];
        let mut first = Vec::new();
        let mut second = Vec::new();

        run_campaign(seeds, 64, 42, |input| first.push(input.to_vec()));
        run_campaign(seeds, 64, 42, |input| second.push(input.to_vec()));

        assert_eq!(first, second);
        assert!(first.iter().any(|item| item == b""));
        assert!(first.iter().any(|item| item == b"A"));
        assert!(first.iter().any(|item| item == b"BCD"));
    }
}
