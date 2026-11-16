//! Consolidated `aws-lc-sys` FFI boundary.
//!
//! Every `unsafe` block and raw C call in `netune-tls` lives in this module so
//! external audits and sanitizer runs have a single, self-contained boundary to
//! inspect ([`INV-TLS-05`]).
//!
//! The `aws-lc-rs` safe facade covers modern AEAD, HKDF, HMAC, ECDH, ML-KEM
//! and single-hash TLS 1.2 PRFs (`P_SHA256`, `P_SHA384`). Only the three legacy
//! primitives the safe facade deliberately omits cross this boundary:
//!
//! 1. [`cbc_transform`] — raw AES-CBC without PKCS#7 padding and with a
//!    caller-supplied IV (for TLS 1.2 CBC suites);
//! 2. [`md5_sha1_prf`] — the TLS 1.0–1.2 MD5+SHA-1 dual PRF (`EVP_md5_sha1`);
//! 3. [`md5`] — raw MD5 digest for the legacy TLS 1.2 Finished transcript hash.

use aws_lc_rs::error::Unspecified;
use aws_lc_sys::{
    CRYPTO_tls1_prf, EVP_CIPHER_CTX_free, EVP_CIPHER_CTX_new, EVP_CIPHER_CTX_set_padding,
    EVP_DecryptFinal_ex, EVP_DecryptInit_ex, EVP_DecryptUpdate, EVP_Digest, EVP_EncryptFinal_ex,
    EVP_EncryptInit_ex, EVP_EncryptUpdate, EVP_aes_128_cbc, EVP_aes_256_cbc, EVP_md5, EVP_md5_sha1,
};

use crate::key_schedule::ScheduleError;
use crate::zeroize::wipe;

/// Raw AES-CBC over an already block-aligned buffer, with a caller-chosen
/// IV, through the `aws-lc` EVP interface.
pub(crate) fn cbc_transform(
    bits: u16,
    key: &[u8],
    iv: [u8; 16],
    input: &[u8],
    encrypting: bool,
) -> Result<Vec<u8>, Unspecified> {
    let expected_key_len = match bits {
        128 => 16,
        256 => 32,
        _ => return Err(Unspecified),
    };
    if key.len() != expected_key_len || input.is_empty() || !input.len().is_multiple_of(16) {
        return Err(Unspecified);
    }
    let input_len = i32::try_from(input.len()).map_err(|_| Unspecified)?;
    // SAFETY: `EVP_aes_128_cbc()` / `EVP_aes_256_cbc()` return static cipher
    // descriptors with `'static` lifetime; no state is mutated.
    let cipher = unsafe {
        match bits {
            128 => EVP_aes_128_cbc(),
            256 => EVP_aes_256_cbc(),
            _ => unreachable!("checked above"),
        }
    };
    // SAFETY:
    // - `context` is freshly allocated by `EVP_CIPHER_CTX_new()` and checked
    //   non-null before any use; it is freed once before returning regardless of
    //   success or error.
    // - `key` has length `expected_key_len` (16 or 32 bytes matching the cipher)
    //   and `iv` is `[u8; 16]`, satisfying `EVP_EncryptInit_ex` /
    //   `EVP_DecryptInit_ex` preconditions.
    // - With padding disabled (`EVP_CIPHER_CTX_set_padding(context, 0)`), an
    //   input of `input.len()` bytes produces at most `input.len()` bytes across
    //   `update` + `final_ex`, so `output` allocated with `input.len() + 16`
    //   bytes always has sufficient capacity and `output.as_mut_ptr().add(total)`
    //   remains within the allocation.
    unsafe {
        let context = EVP_CIPHER_CTX_new();
        if context.is_null() {
            return Err(Unspecified);
        }
        let mut output = vec![0u8; input.len() + 16];
        let result = (|| {
            let init = if encrypting {
                EVP_EncryptInit_ex(
                    context,
                    cipher,
                    core::ptr::null_mut(),
                    key.as_ptr(),
                    iv.as_ptr(),
                )
            } else {
                EVP_DecryptInit_ex(
                    context,
                    cipher,
                    core::ptr::null_mut(),
                    key.as_ptr(),
                    iv.as_ptr(),
                )
            };
            if init != 1 || EVP_CIPHER_CTX_set_padding(context, 0) != 1 {
                return Err(Unspecified);
            }
            let (update, final_ex): (
                unsafe extern "C" fn(
                    *mut aws_lc_sys::EVP_CIPHER_CTX,
                    *mut u8,
                    *mut i32,
                    *const u8,
                    i32,
                ) -> i32,
                unsafe extern "C" fn(*mut aws_lc_sys::EVP_CIPHER_CTX, *mut u8, *mut i32) -> i32,
            ) = if encrypting {
                (EVP_EncryptUpdate, EVP_EncryptFinal_ex)
            } else {
                (EVP_DecryptUpdate, EVP_DecryptFinal_ex)
            };
            let mut written = 0i32;
            if update(
                context,
                output.as_mut_ptr(),
                &mut written,
                input.as_ptr(),
                input_len,
            ) != 1
            {
                return Err(Unspecified);
            }
            let total = usize::try_from(written).map_err(|_| Unspecified)?;
            if total > input.len() {
                return Err(Unspecified);
            }
            if final_ex(context, output.as_mut_ptr().add(total), &mut written) != 1 || written != 0
            {
                return Err(Unspecified);
            }
            output.truncate(total);
            Ok(())
        })();
        EVP_CIPHER_CTX_free(context);
        match result {
            Ok(()) => Ok(output),
            Err(err) => {
                wipe(&mut output);
                Err(err)
            }
        }
    }
}

/// The TLS 1.2 MD5+SHA-1 dual PRF (`EVP_md5_sha1`), through `aws-lc-sys`.
pub(crate) fn md5_sha1_prf(
    secret: &[u8],
    label: &[u8],
    seed: &[u8],
    length: usize,
) -> Result<Vec<u8>, ScheduleError> {
    if secret.is_empty() || length == 0 {
        return Err(ScheduleError::Expand(Unspecified));
    }
    let mut out = vec![0u8; length];
    // SAFETY:
    // - `EVP_md5_sha1()` returns a `'static` digest descriptor.
    // - `out` is a writable buffer of `out.len()` bytes; `secret`, `label`, and
    //   `seed` are valid immutable slices for the duration of the call; the
    //   second seed pointer is null with length 0 as allowed by `CRYPTO_tls1_prf`.
    let written = unsafe {
        CRYPTO_tls1_prf(
            EVP_md5_sha1(),
            out.as_mut_ptr(),
            out.len(),
            secret.as_ptr(),
            secret.len(),
            label.as_ptr().cast(),
            label.len(),
            seed.as_ptr(),
            seed.len(),
            core::ptr::null(),
            0,
        )
    };
    if written != 1 {
        wipe(&mut out);
        return Err(ScheduleError::Expand(Unspecified));
    }
    Ok(out)
}

/// Raw MD5 digest, through `aws-lc-sys` (for TLS 1.2 legacy Finished hashes).
pub(crate) fn md5(data: &[u8]) -> [u8; 16] {
    let mut out = [0u8; 16];
    let mut written = 0u32;
    // SAFETY:
    // - `EVP_md5()` returns a `'static` 16-byte digest descriptor.
    // - `data` is a valid immutable slice of `data.len()` bytes; `out` is a
    //   writable 16-byte array receiving the MD5 digest and `written` receives
    //   its length (16).
    let result = unsafe {
        EVP_Digest(
            data.as_ptr().cast(),
            data.len(),
            out.as_mut_ptr(),
            &mut written,
            EVP_md5(),
            core::ptr::null_mut(),
        )
    };
    debug_assert!(
        result == 1 && written == 16,
        "MD5 through aws-lc cannot fail"
    );
    out
}

/// Volatile zeroization primitive for secret-bearing slices.
pub(crate) fn volatile_zeroize(bytes: &mut [u8]) {
    for byte in bytes.iter_mut() {
        // SAFETY: `byte` is a unique, valid, aligned `&mut u8` inside `bytes`.
        unsafe { core::ptr::write_volatile(byte, 0) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}
