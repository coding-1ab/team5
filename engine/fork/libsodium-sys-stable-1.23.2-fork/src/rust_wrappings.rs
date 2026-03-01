use core::error::Error;
use core::ffi::c_void;
use core::intrinsics::transmute;
use core::ptr::{addr_of_mut, copy, slice_from_raw_parts};
use libc::{c_uchar, c_ulonglong, malloc};
use crate::{crypto_aead_aes256gcm_ABYTES, crypto_aead_aes256gcm_beforenm, crypto_aead_aes256gcm_decrypt, crypto_aead_aes256gcm_decrypt_afternm, crypto_aead_aes256gcm_encrypt, crypto_aead_aes256gcm_encrypt_afternm, crypto_generichash_blake2b_final, crypto_generichash_blake2b_init, crypto_generichash_blake2b_init_salt_personal, crypto_generichash_blake2b_update, crypto_scalarmult, crypto_scalarmult_curve25519_base, randombytes_buf, sodium_free, sodium_malloc, sodium_memzero};


/// utility

const NULL: *const c_void = unsafe { transmute::<usize, *const c_void>(0usize) };

pub struct SodiumBox<T> {
    ptr: *mut T,
    len: usize,
}
impl<T> SodiumBox<T> {
    pub fn new_with_size(len: usize) -> SodiumBox<T> {
        let ptr: *mut T = unsafe {
            sodium_malloc(len * size_of::<T>()).cast()
        };
        Self {ptr, len}
    }
    pub fn from_raw(ptr: *mut T, len: usize) -> SodiumBox<T> {
        Self { ptr, len }
    }
    pub fn from_slice(s: &[T]) -> SodiumBox<T> {
        unsafe {
            let ptr: *mut T = sodium_malloc(s.len() * size_of::<T>()).cast();
            ptr.copy_from(s.as_ptr(), s.len());
            Self {ptr, len: s.len()}
        }
    }
    pub fn as_ptr(&self) -> *const T {
        self.ptr.cast_const()
    }
    pub fn as_mut_ptr(&mut self) -> *mut T {
        self.ptr
    }
    pub fn zeroize(&mut self) {
        unsafe {
            sodium_memzero(self.ptr.cast(), self.len * size_of::<T>());
        }
    }
}
impl<T> Drop for SodiumBox<T> {
    fn drop(&mut self) {
        unsafe {
            sodium_free(self.ptr.cast());
        }
    }
}


/// curve_25519

pub const ECIES_PK_SIZE: usize = 65;
pub struct PubKey (
    [u8; ECIES_PK_SIZE],
);
impl PubKey {
    pub fn from_sec_key(sk: &SecKey) -> Self {
        let mut pk = [0u8; 65];

        let rc = unsafe {
            crypto_scalarmult_curve25519_base(pk.as_mut_ptr(), sk.as_ptr())
        };
        assert_eq!(rc, 0);

        PubKey (pk)
    }
    pub fn from_slice(slice: &[u8]) -> Self {
        let arr = slice.try_into().unwrap();
        Self {0: arr}
    }
    pub fn as_ptr(&self) -> *const u8 {
        self.0.as_ptr()
    }
    pub fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }
    pub fn get(&self) -> &[u8; ECIES_PK_SIZE] {
        &self.0
    }
}

pub const ECIES_SK_SIZE: usize = 32;
pub struct SecKey {
    ptr: *mut u8
}
impl SecKey {
    const SIZE: usize = ECIES_SK_SIZE;
    pub fn gen_rand() -> Self {
        unsafe {
            let ptr = sodium_malloc(Self::SIZE);

            randombytes_buf(ptr, Self::SIZE);

            Self {ptr: ptr.cast()}
        }
    }
    pub fn from_array(arr: [u8; ECIES_SK_SIZE]) -> Self {
        unsafe {
            let ptr: *mut u8 = sodium_malloc(Self::SIZE).cast();
            
            ptr.copy_from(arr.as_ptr(), Self::SIZE);

            Self {ptr}
        }
    }
    fn as_ptr(&self) -> *const u8 {
        self.ptr.cast_const()
    }
    pub fn as_slice(&self) -> &[u8] {
        unsafe {
            &*slice_from_raw_parts(self.ptr, Self::SIZE)
        }
    }
    pub fn zeroize(&mut self) {
        unsafe {
            sodium_memzero(self.ptr, Self::SIZE);
        }
    }
}
impl Drop for SecKey {
    fn drop(&mut self) {
        unsafe {
            sodium_free(self.ptr.cast())
        }
    }
}

pub const ECIES_SHARED_SECRET_SIZE: usize = 32;
pub struct SharedSecret {
    ptr: *mut u8
}
impl SharedSecret {
    const SIZE: usize = ECIES_SHARED_SECRET_SIZE;
    pub fn from_sk_pk(sk: &SecKey, pk: &PubKey) -> Self {
        unsafe {
            let ptr: *mut u8 = sodium_malloc(Self::SIZE).cast();

            let rc = crypto_scalarmult(ptr, sk.as_ptr(), pk.as_ptr());
            assert_eq!(rc, 0);

            Self { ptr }
        }
    }
    fn as_ptr(&self) -> *const u8 {
        self.ptr.cast_const()
    }
    fn as_slice(&self) -> &[u8] {
        unsafe {
            &*slice_from_raw_parts(self.ptr, ECIES_SHARED_SECRET_SIZE)
        }
    }
    pub fn zeroize(&mut self) {
        unsafe {
            sodium_memzero(self.ptr as *mut libc::c_uchar, Self::SIZE);
        }
    }
}
impl Drop for SharedSecret {
    fn drop(&mut self) {
        unsafe {
            sodium_free(self.ptr.cast())
        }
    }
}


// blake2b

pub const BLAKE2B_STATE_SIZE: usize = 384;
struct Blake2bState<const out_len: usize> {
    ptr: *mut u8
}
impl<const out_len: usize> Blake2bState<out_len> {
    const SIZE: usize = BLAKE2B_STATE_SIZE;
    pub fn new() -> Self{
        unsafe {
            let ptr = sodium_malloc(Self::SIZE);

            crypto_generichash_blake2b_init(ptr.cast(), NULL.cast(), 0, out_len);

            Blake2bState {ptr: ptr.cast()}
        }
    }
    pub fn update(&mut self, data: &[u8]) {
        unsafe {
            crypto_generichash_blake2b_update(self.ptr.cast(), data.as_ptr(), data.len() as c_ulonglong);
        }
    }
    pub fn finalize_write_to(self, dst: *mut u8) {
        unsafe {
            crypto_generichash_blake2b_final(self.ptr.cast(), dst, out_len);
        }
    }
    pub fn zeroize(&mut self) {
        unsafe {
            sodium_memzero(self.ptr.cast(), Self::SIZE);
        }
    }
}
impl<const out_len: usize> Drop for Blake2bState<out_len> {
    fn drop(&mut self) {
        unsafe {
            sodium_free(self.ptr.cast())
        }
    }
}


/// aes256_gcm

pub const AES_KEY_SIZE: usize = 32;
pub struct AesKey {
    ptr: *mut u8
}
impl AesKey {
    const SIZE: usize = AES_KEY_SIZE;
    pub fn from_shared_secret(shared: &SharedSecret) -> Self {
        unsafe {
            let halo = &[95u8, 213, 252, 194, 137, 54, 67, 46, 29, 206, 72, 249, 3, 152, 242, 90, 219, 64, 130, 21, 7, 96, 24, 187, 85, 69, 81, 233, 218, 40, 105, 233];
            let mut hasher = Blake2bState::<{ Self::SIZE }>::new();
            hasher.update(halo);
            hasher.update(shared.as_slice());
            let ptr: *mut u8 = sodium_malloc(Self::SIZE).cast();
            hasher.finalize_write_to(ptr);
            Self {ptr}
        }
    }
    pub fn as_ptr(&self) -> *const u8 {
        self.ptr.cast_const()
    }
    pub fn as_slice(&self) -> &[u8] {
        unsafe {
            &*slice_from_raw_parts(self.ptr, Self::SIZE)
        }
    }
    pub fn zeroize(&mut self) {
        unsafe {
            sodium_memzero(self.ptr, Self::SIZE)
        }
    }
}
impl Drop for AesKey {
    fn drop(&mut self) {
        unsafe {
            sodium_free(self.ptr.cast())
        }
    }
}

pub const AES_NONCE_SIZE: usize = 12;
pub struct AesNonce {
    nonce: [u8; AES_NONCE_SIZE]
}
impl AesNonce {
    const SIZE: usize = AES_NONCE_SIZE;
    pub fn gen_rand() -> Self {
        unsafe {
            let mut nonce = [0u8; _];
            randombytes_buf(nonce.as_mut_ptr().cast(), Self::SIZE);
            Self { nonce }
        }
    }
    pub fn as_ptr(&self) -> *const u8 {
        self.nonce.as_ptr()
    }
    pub fn as_slice(&self) -> &[u8] {
        unsafe {
            &*slice_from_raw_parts(self.nonce.as_ptr(), self.nonce.len())
        }
    }
    pub fn get(&self) -> &[u8; AES_NONCE_SIZE] {
        &self.nonce
    }
}


pub fn aes256_encrypt(key: &AesKey, nonce: &AesNonce, plaintext: &[u8]) -> SodiumBox<u8> {
    let mut raw_ciphertext_len: c_ulonglong = 0;
    let ciphertext_len = plaintext.len() as c_ulonglong + crypto_aead_aes256gcm_ABYTES as c_ulonglong;
    let mut ciphertext = SodiumBox::new_with_size(ciphertext_len as usize);
    unsafe {
        crypto_aead_aes256gcm_encrypt(
            ciphertext.as_mut_ptr(), addr_of_mut!(raw_ciphertext_len),
            plaintext.as_ptr(), plaintext.len() as c_ulonglong,
            NULL.cast(), 0,
            NULL.cast(), nonce.as_ptr(), key.as_ptr()
        );
    }
    assert_eq!(raw_ciphertext_len, ciphertext_len, "AES-GCM ciphertext length mismatch of {{ plaintext length + verifier tag langth (16) }}");
    ciphertext
}

pub fn aes256_decrypt(key: &AesKey, nonce: &AesNonce, ciphertext: &[u8]) -> Result<SodiumBox<u8>, ()> {
    let mut raw_plaintext_len: c_ulonglong = 0;
    let plaintext_len = ciphertext.len() as c_ulonglong - crypto_aead_aes256gcm_ABYTES as c_ulonglong;
    let mut plaintext = SodiumBox::<c_uchar>::new_with_size(plaintext_len as usize);
    let rc = unsafe {
        crypto_aead_aes256gcm_decrypt(
            plaintext.as_mut_ptr(), addr_of_mut!(raw_plaintext_len), *NULL.cast(),
            ciphertext.as_ptr(), plaintext_len as c_ulonglong,
            NULL.cast(), 0,
            nonce.as_ptr(), key.as_ptr()
        )
    };
    assert_eq!(raw_plaintext_len, plaintext_len, "AES-GCM ciphertext length mismatch of {{ plaintext length - verifier tag langth (16) }}");
    if rc != 0 {
        return Err( () )
    }
    Ok ( plaintext )
}

// pub fn aes256gcm_beforenm() -> libc::c_int{
//     crypto_aead_aes256gcm_beforenm()
// }

// pub fn aes256_encrypt_afterenm(key: &AesKey, nonce: &AesNonce, plaintext: &[u8]) -> SodiumBox<u8> {
//     let mut raw_ciphertext_len: c_ulonglong = 0;
//     let ciphertext_len = plaintext.len() as c_ulonglong + crypto_aead_aes256gcm_ABYTES as c_ulonglong;
//     let mut ciphertext = SodiumBox::new_with_size(ciphertext_len as usize);
//     unsafe {
//         crypto_aead_aes256gcm_encrypt_afternm(
//             ciphertext.as_mut_ptr(), addr_of_mut!(raw_ciphertext_len),
//             plaintext.as_ptr(), plaintext.len() as c_ulonglong,
//             NULL.cast(), 0,
//             NULL.cast(), nonce.as_ptr(), key.as_ptr()
//         );
//     }
//     assert_eq!(raw_ciphertext_len, ciphertext_len, "AES-GCM ciphertext length mismatch of {{ plaintext length + verifier tag langth (16) }}");
//     ciphertext
// }
//
// pub fn aes256_decrypt_afterenm(key: &AesKey, nonce: &AesNonce, ciphertext: &[u8]) -> Result<SodiumBox<u8>, ()> {
//     let mut raw_plaintext_len: c_ulonglong = 0;
//     let plaintext_len = ciphertext.len() as c_ulonglong - crypto_aead_aes256gcm_ABYTES as c_ulonglong;
//     let mut plaintext = SodiumBox::<c_uchar>::new_with_size(plaintext_len as usize);
//     let rc = unsafe {
//         crypto_aead_aes256gcm_decrypt_afternm(
//             plaintext.as_mut_ptr(), addr_of_mut!(raw_plaintext_len), *NULL.cast(),
//             ciphertext.as_ptr(), plaintext_len as c_ulonglong,
//             NULL.cast(), 0,
//             nonce.as_ptr(), key.as_ptr()
//         )
//     };
//     assert_eq!(raw_plaintext_len, plaintext_len, "AES-GCM ciphertext length mismatch of {{ plaintext length - verifier tag langth (16) }}");
//     if rc != 0 {
//         return Err( () )
//     }
//     Ok ( plaintext )
// }
