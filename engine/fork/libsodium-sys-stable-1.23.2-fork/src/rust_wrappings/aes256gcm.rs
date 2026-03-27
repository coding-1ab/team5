use alloc::vec::Vec;
use core::ffi::{c_uchar, c_ulonglong};
use core::ptr::{addr_of_mut, null, null_mut};
use zeroize::Zeroize;
use crate::rust_wrappings::sodium_box::SodiumBox;
use crate::sodium_bindings::{crypto_aead_aes256gcm_ABYTES, crypto_aead_aes256gcm_decrypt, crypto_aead_aes256gcm_encrypt, randombytes_buf};



pub const AES_KEY_SIZE: usize = 32;
pub struct AesKey {
    inner: SodiumBox<u8>,
}
impl AesKey {
    const SIZE: usize = AES_KEY_SIZE;
    pub fn from_raw(src: *const u8) -> Self {
        let boxed = SodiumBox::from_raw(src, Self::SIZE);
        Self {inner: boxed}
    }
    pub fn from_sodium_box(boxed : SodiumBox<u8>) -> Self {
        Self {inner: boxed}
    }
    pub fn as_ptr(&self) -> *const u8 {
        self.inner.as_ptr()
    }
    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.inner.as_mut_ptr()
    }
    pub fn copy_to(&self, dst: *mut u8) {
        self.inner.copy_to(dst);
    }
    pub fn zeroize(&mut self) {
        self.inner.zeroize();
    }
}
impl Default for AesKey {
    fn default() -> Self {
        Self {inner: SodiumBox::new_with_size(Self::SIZE)}
    }
}

pub const AES_NONCE_SIZE: usize = 12;
pub struct AesNonce {
    inner: SodiumBox<u8>
}
impl AesNonce {
    const SIZE: usize = AES_NONCE_SIZE;
    pub fn gen_rand() -> Self {
        unsafe {
            let mut boxed: SodiumBox<u8> = SodiumBox::new_with_size(Self::SIZE);
            randombytes_buf(boxed.as_mut_ptr().cast(), Self::SIZE);
            Self { inner: boxed }
        }
    }
    pub fn from_raw(src: *const u8) -> Self {
        let boxed = SodiumBox::from_raw(src, Self::SIZE);
        Self {inner: boxed}
    }
    pub fn as_ptr(&self) -> *const u8 {
        self.inner.as_ptr()
    }
    pub fn copy_to(&self, dst: *mut u8) {
        self.inner.copy_to(dst);
    }
    pub fn zeroize(&mut self) {
        self.inner.zeroize();
    }
}
impl Default for AesNonce {
    fn default() -> Self {
        Self {inner: SodiumBox::new_with_size(Self::SIZE)}
    }
}

pub const AES_OUT_AUTH_TAG_SIZE: usize = crypto_aead_aes256gcm_ABYTES as usize;


/// encrypt

pub fn aes256gcm_encrypt(
    key: &AesKey, nonce: &AesNonce,
    plaintext: &[u8]
) -> Vec<u8> {
    let mut actual_ciphertext_len: c_ulonglong = 0;
    let ciphertext_len = plaintext.len() as c_ulonglong + AES_OUT_AUTH_TAG_SIZE as c_ulonglong;
    let mut ciphertext = Vec::with_capacity(ciphertext_len as usize);
    unsafe { ciphertext.set_len(ciphertext_len as usize); }
    unsafe {
        crypto_aead_aes256gcm_encrypt(
            ciphertext.as_mut_ptr(), addr_of_mut!(actual_ciphertext_len),
            plaintext.as_ptr(), plaintext.len() as c_ulonglong,
            null(), 0,
            null(), nonce.as_ptr(), key.as_ptr()
        );
    }
    assert_eq!(actual_ciphertext_len, ciphertext_len, "AES-GCM ciphertext length mismatch of {{ plaintext length + verifier tag langth (16) }}");
    ciphertext
}


pub fn aes256gcm_encrypt_from_ptr(
    key: &AesKey, nonce: &AesNonce,
    plaintext: *const u8, plaintext_len: usize
) -> Vec<u8> {
    let mut actual_ciphertext_len: c_ulonglong = 0;
    let ciphertext_len = plaintext_len as c_ulonglong + AES_OUT_AUTH_TAG_SIZE as c_ulonglong;
    let mut ciphertext = Vec::with_capacity(ciphertext_len as usize);
    unsafe { ciphertext.set_len(ciphertext_len as usize); }
    unsafe {
        crypto_aead_aes256gcm_encrypt(
            ciphertext.as_mut_ptr(), addr_of_mut!(actual_ciphertext_len),
            plaintext, plaintext_len as c_ulonglong,
            null(), 0,
            null(), nonce.as_ptr(), key.as_ptr()
        );
    }
    assert_eq!(actual_ciphertext_len, ciphertext_len, "AES-GCM ciphertext length mismatch of {{ plaintext length + verifier tag langth (16) }}");
    ciphertext
}

pub fn aes256gcm_encrypt_from_ptr_to_sodium_box(
    key: &AesKey, nonce: &AesNonce,
    plaintext: *const u8, plaintext_len: usize,
) -> SodiumBox<u8> {
    let mut actual_ciphertext_len: c_ulonglong = 0;
    let ciphertext_len = plaintext_len as c_ulonglong + AES_OUT_AUTH_TAG_SIZE as c_ulonglong;
    let mut ciphertext = SodiumBox::<u8>::new_with_size(ciphertext_len as usize);
    if unsafe {
        crypto_aead_aes256gcm_encrypt(
            ciphertext.as_mut_ptr(), addr_of_mut!(actual_ciphertext_len),
            plaintext, plaintext_len as c_ulonglong,
            null(), 0,
            null(), nonce.as_ptr(), key.as_ptr()
        )
    } != 0 {
        panic!()
    }
    assert_eq!(actual_ciphertext_len, ciphertext_len, "AES-GCM ciphertext length mismatch of {{ plaintext length + verifier tag langth (16) }}");
    ciphertext
}

pub fn aes256gcm_encrypt_to_sodium_box(
    key: &AesKey, nonce: &AesNonce,
    plaintext: &[u8]
) -> SodiumBox<u8> {
    let mut actual_ciphertext_len: c_ulonglong = 0;
    let ciphertext_len = plaintext.len() as c_ulonglong + AES_OUT_AUTH_TAG_SIZE as c_ulonglong;
    let mut ciphertext = SodiumBox::<u8>::new_with_size(ciphertext_len as usize);
    unsafe {
        crypto_aead_aes256gcm_encrypt(
            ciphertext.as_mut_ptr(), addr_of_mut!(actual_ciphertext_len),
            plaintext.as_ptr(), plaintext.len() as c_ulonglong,
            null(), 0,
            null(), nonce.as_ptr(), key.as_ptr()
        );
    }
    assert_eq!(actual_ciphertext_len, ciphertext_len, "AES-GCM ciphertext length mismatch of {{ plaintext length + verifier tag langth (16) }}");
    ciphertext
}

pub fn aes256gcm_encrypt_to_slice(
    key: &AesKey, nonce: &AesNonce,
    plaintext: &[u8],
    ciphertext: &mut [u8]
) -> () {
    let mut actual_ciphertext_len: c_ulonglong = 0;
    let ciphertext_len = plaintext.len() as c_ulonglong + AES_OUT_AUTH_TAG_SIZE as c_ulonglong;
    unsafe {
        crypto_aead_aes256gcm_encrypt(
            ciphertext.as_mut_ptr(), addr_of_mut!(actual_ciphertext_len),
            plaintext.as_ptr(), plaintext.len() as c_ulonglong,
            null(), 0,
            null(), nonce.as_ptr(), key.as_ptr()
        );
    }
    assert_eq!(actual_ciphertext_len, ciphertext_len, "AES-GCM ciphertext length mismatch of {{ plaintext length + verifier tag langth (16) }}");
}


/// decrypt

pub fn aes256gcm_decrypt(
    key: &AesKey, nonce: &AesNonce,
    ciphertext: &[u8]
) -> Result<SodiumBox<u8>, ()> {
    let mut actual_plaintext_len: c_ulonglong = 0;
    let plaintext_len = ciphertext.len() as c_ulonglong - crypto_aead_aes256gcm_ABYTES as c_ulonglong;
    let mut plaintext = SodiumBox::<c_uchar>::new_with_size(plaintext_len as usize);
    let rc = unsafe {
        crypto_aead_aes256gcm_decrypt(
            plaintext.as_mut_ptr(), addr_of_mut!(actual_plaintext_len), null_mut(),
            ciphertext.as_ptr(), ciphertext.len() as c_ulonglong,
            null(), 0,
            nonce.as_ptr(), key.as_ptr()
        )
    };
    if rc != 0 {
        return Err( () )
    }
    assert_eq!(actual_plaintext_len, plaintext_len, "AES-GCM ciphertext length mismatch of {{ plaintext length - verifier tag langth (16) }}");
    Ok ( plaintext )
}

pub fn aes256gcm_decrypt_from_ptr(
    key: &AesKey, nonce: &AesNonce,
    ciphertext: *const u8, ciphertext_len: usize
) -> Result<SodiumBox<u8>, ()> {
    let mut actual_plaintext_len: c_ulonglong = 0;
    let plaintext_len = ciphertext_len as c_ulonglong - crypto_aead_aes256gcm_ABYTES as c_ulonglong;
    let mut plaintext = SodiumBox::<c_uchar>::new_with_size(plaintext_len as usize);
    let rc = unsafe {
        crypto_aead_aes256gcm_decrypt(
            plaintext.as_mut_ptr(), addr_of_mut!(actual_plaintext_len), null_mut(),
            ciphertext, ciphertext_len as c_ulonglong,
            null(), 0,
            nonce.as_ptr(), key.as_ptr()
        )
    };
    if rc != 0 {
        return Err( () )
    }
    assert_eq!(actual_plaintext_len, plaintext_len, "AES-GCM ciphertext length mismatch of {{ plaintext length - verifier tag langth (16) }}");
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