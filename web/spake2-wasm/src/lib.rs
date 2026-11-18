//! Minimal C-ABI WebAssembly wrapper around the `spake2` crate (no wasm-bindgen needed).
//! JS passes a 32-byte seed from `crypto.getRandomValues`; results are read from `wh_out()`.

use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use spake2::{Ed25519Group, Identity, Password, Spake2};
use std::cell::RefCell;

thread_local! {
    static STATE: RefCell<Option<Spake2<Ed25519Group>>> = const { RefCell::new(None) };
    static OUT: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

#[no_mangle]
pub extern "C" fn wh_alloc(n: usize) -> *mut u8 {
    let mut v = Vec::<u8>::with_capacity(n);
    let p = v.as_mut_ptr();
    std::mem::forget(v);
    p
}

/// # Safety
/// `p` must come from `wh_alloc(n)`.
#[no_mangle]
pub unsafe extern "C" fn wh_free(p: *mut u8, n: usize) {
    drop(Vec::from_raw_parts(p, 0, n));
}

#[no_mangle]
pub extern "C" fn wh_out() -> *const u8 {
    OUT.with(|o| o.borrow().as_ptr())
}

/// Start a symmetric SPAKE2 exchange. Returns the length of the outbound message in `wh_out()`.
///
/// # Safety
/// Pointers must be valid for the given lengths; `seed` must point to 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn wh_start(pw: *const u8, pw_len: usize, seed: *const u8) -> usize {
    let pw = std::slice::from_raw_parts(pw, pw_len);
    let mut s = [0u8; 32];
    s.copy_from_slice(std::slice::from_raw_parts(seed, 32));
    let rng = ChaCha20Rng::from_seed(s);
    let (state, msg) =
        Spake2::<Ed25519Group>::start_symmetric_with_rng(&Password::new(pw), &Identity::new(b"wormhole-v1"), rng);
    STATE.with(|st| *st.borrow_mut() = Some(state));
    let n = msg.len();
    OUT.with(|o| *o.borrow_mut() = msg);
    n
}

/// Finish with the peer's message. Returns the key length (32) in `wh_out()`, or -1 on failure.
///
/// # Safety
/// `msg` must be valid for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn wh_finish(msg: *const u8, len: usize) -> isize {
    let msg = std::slice::from_raw_parts(msg, len);
    let Some(state) = STATE.with(|st| st.borrow_mut().take()) else { return -1 };
    match state.finish(msg) {
        Ok(key) => {
            let n = key.len() as isize;
            OUT.with(|o| *o.borrow_mut() = key);
            n
        }
        Err(_) => -1,
    }
}
