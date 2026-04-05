use crate::rust_wrappings::sodium_box::SodiumBox;
use crate::sodium_bindings::{
    crypto_generichash_blake2b_final, crypto_generichash_blake2b_init,
    crypto_generichash_blake2b_state, crypto_generichash_blake2b_update, crypto_hash_sha256_final,
    crypto_hash_sha256_init, crypto_hash_sha256_state, crypto_hash_sha256_update, sodium_memzero,
};
use core::ptr::null;
use libc::c_ulonglong;
use zeroize::Zeroize;

/// blake2b
pub const BLAKE2B_BLOCK_SIZE: usize = 128;
pub const BLAKE2B_STATE_SIZE: usize = size_of::<crypto_generichash_blake2b_state>();
pub struct Blake2b<const out_len: usize> {
    inner: SodiumBox<u8>,
    begin: *mut crypto_generichash_blake2b_state,
}
impl<const out_len: usize> Blake2b<out_len> {
    const STATE_SIZE: usize = BLAKE2B_STATE_SIZE;
    const ALIGN_BYTES: usize = 64;
    const MEM_SIZE: usize = BLAKE2B_STATE_SIZE + Self::ALIGN_BYTES;
    pub fn new() -> Self {
        unsafe {
            let mut boxed: SodiumBox<u8> = SodiumBox::new_with_size(Self::MEM_SIZE);
            let redundant = boxed.as_ptr() as usize % Self::ALIGN_BYTES;
            let diff_begin = Self::ALIGN_BYTES - redundant;
            let begin = boxed.as_mut_ptr().add(diff_begin).cast();

            crypto_generichash_blake2b_init(begin, null(), 0, out_len);

            Blake2b {
                inner: boxed,
                begin,
            }
        }
    }
    pub fn update(&mut self, data: &[u8]) {
        unsafe {
            crypto_generichash_blake2b_update(self.begin, data.as_ptr(), data.len() as c_ulonglong);
        }
    }
    pub fn update_from_ptr(&mut self, data: *const u8, len: usize) {
        unsafe {
            crypto_generichash_blake2b_update(self.begin, data, len as c_ulonglong);
        }
    }
    pub fn finalize_write_to(mut self, dst: *mut u8) {
        unsafe {
            crypto_generichash_blake2b_final(self.begin, dst, out_len);
        }
    }
    pub fn zeroize(&mut self) {
        unsafe {
            sodium_memzero(self.begin.cast(), Self::STATE_SIZE);
        };
    }
}

/// sha256
const SHA256_BLOCK_SIZE: usize = 64;
const SHA256_STATE_SIZE: usize = size_of::<crypto_hash_sha256_state>();
pub struct Sha256 {
    inner: SodiumBox<crypto_hash_sha256_state>,
}
impl Sha256 {
    const SIZE: usize = SHA256_STATE_SIZE;
    pub fn new() -> Self {
        unsafe {
            let mut boxed: SodiumBox<crypto_hash_sha256_state> = SodiumBox::new_with_size(1);

            crypto_hash_sha256_init(boxed.as_mut_ptr().cast());

            Self { inner: boxed }
        }
    }
    pub fn update(&mut self, data: &[u8]) {
        unsafe {
            crypto_hash_sha256_update(
                self.inner.as_mut_ptr(),
                data.as_ptr(),
                data.len() as c_ulonglong,
            );
        }
    }
    pub fn update_from_ptr(&mut self, data: *const u8, len: usize) {
        unsafe {
            crypto_hash_sha256_update(self.inner.as_mut_ptr(), data, len as c_ulonglong);
        }
    }
    pub fn finalize_write_to(mut self, dst: *mut u8) {
        unsafe {
            crypto_hash_sha256_final(self.inner.as_mut_ptr(), dst);
        }
    }
    pub fn zeroize(&mut self) {
        self.inner.zeroize();
    }
}
