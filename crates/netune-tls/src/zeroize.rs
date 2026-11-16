//! Memory-hygiene primitives for secret-bearing TLS buffers.
//!
//! Ordinary `slice.fill(0)` inside `Drop` can be eliminated as a dead store by
//! optimizing compilers when the buffer is about to be deallocated. Every
//! secret-bearing wipe in this crate delegates to [`crate::ffi::volatile_zeroize`].

/// Overwrite `bytes` with zeros in a way the optimizer cannot elide.
pub(crate) fn wipe(bytes: &mut [u8]) {
    crate::ffi::volatile_zeroize(bytes);
}

/// Overwrite an `Option<Vec<u8>>` with zeros before discarding it.
pub(crate) fn wipe_option(opt: &mut Option<Vec<u8>>) {
    if let Some(mut buf) = opt.take() {
        wipe(&mut buf);
    }
}
