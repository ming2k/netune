use std::sync::atomic::{AtomicU64, Ordering};
use std::time::SystemTime;

static MASK_COUNTER: AtomicU64 = AtomicU64::new(0x2545f4914f6cdd1d);

/// Generate an unpredictable 4-byte masking key for client-to-server frames.
pub fn generate_mask() -> [u8; 4] {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let count = MASK_COUNTER.fetch_add(0x9e3779b97f4a7c15, Ordering::Relaxed);
    let mut state = (now as u64) ^ count ^ 0xbf58476d1ce4e5b9;

    // SplitMix64 step
    state = state.wrapping_add(0x9e3779b97f4a7c15);
    let mut z = state;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
    let val = (z ^ (z >> 31)) as u32;

    val.to_ne_bytes()
}

/// Apply in-place XOR masking to a payload slice (RFC 6455 §5.3).
///
/// Uses 64-bit word chunks for high-throughput throughput on modern CPUs,
/// followed by byte-wise handling for remaining tail bytes.
pub fn apply_mask(payload: &mut [u8], mask: [u8; 4]) {
    let len = payload.len();
    if len == 0 {
        return;
    }

    let mut i = 0;
    if len >= 8 {
        let mask_8 = [
            mask[0], mask[1], mask[2], mask[3], mask[0], mask[1], mask[2], mask[3],
        ];
        let mask_u64 = u64::from_ne_bytes(mask_8);

        while i + 8 <= len {
            let chunk = u64::from_ne_bytes(payload[i..i + 8].try_into().unwrap_or([0; 8]));
            let masked = chunk ^ mask_u64;
            payload[i..i + 8].copy_from_slice(&masked.to_ne_bytes());
            i += 8;
        }
    }

    while i < len {
        payload[i] ^= mask[i % 4];
        i += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_apply_mask_matches_naive_and_roundtrips() {
        let mask = [0x12, 0x34, 0x56, 0x78];
        let test_sizes = [
            0, 1, 2, 3, 4, 7, 8, 9, 15, 16, 17, 31, 32, 33, 125, 126, 1024,
        ];

        for &size in &test_sizes {
            let original: Vec<u8> = (0..size).map(|i| (i * 7 + 13) as u8).collect();
            let mut masked = original.clone();
            apply_mask(&mut masked, mask);

            // Verify with naive byte loop
            let mut expected = original.clone();
            for (idx, b) in expected.iter_mut().enumerate() {
                *b ^= mask[idx % 4];
            }
            assert_eq!(masked, expected, "Failed for size {size}");

            // Verify unmasking roundtrip
            let mut unmasked = masked.clone();
            apply_mask(&mut unmasked, mask);
            assert_eq!(unmasked, original, "Roundtrip failed for size {size}");
        }
    }

    #[test]
    fn test_generate_mask_uniqueness() {
        let m1 = generate_mask();
        let m2 = generate_mask();
        assert_ne!(m1, m2);
    }
}
