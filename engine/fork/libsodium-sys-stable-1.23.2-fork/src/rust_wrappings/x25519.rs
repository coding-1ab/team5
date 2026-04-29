use crate::rust_wrappings::aes256gcm::{AesKey, AES_KEY_SIZE};
use crate::rust_wrappings::hasher::Blake2b;
use crate::rust_wrappings::sodium_box::SodiumBox;
use crate::sodium_bindings::{crypto_scalarmult, crypto_scalarmult_curve25519_base, randombytes_buf};

pub const ECIES_PK_SIZE: usize = 65;
#[repr(C)]
pub struct PubKey {
    inner: SodiumBox<u8>,
}
impl PubKey {
    const SIZE: usize = ECIES_PK_SIZE;
    pub fn from_sec_key(sk: &SecKey) -> Self {
        let mut pk = SodiumBox::new_with_size(ECIES_PK_SIZE);

        let rc = unsafe { crypto_scalarmult_curve25519_base(pk.as_mut_ptr(), sk.as_ptr()) };
        assert_eq!(rc, 0);
        
        PubKey { inner: pk }
    }
    pub fn from_raw(src: *const u8) -> Self {
        Self {
            inner: SodiumBox::from_raw(src, Self::SIZE),
        }
    }
    pub fn as_ptr(&self) -> *const u8 {
        self.inner.as_ptr()
    }
    pub fn copy_to(&self, dst: *mut u8) {
        self.inner.copy_to(dst);
    }
}

pub const ECIES_SK_SIZE: usize = 32;
pub struct SecKey {
    inner: SodiumBox<u8>,
}
impl SecKey {
    const SIZE: usize = ECIES_SK_SIZE;
    pub fn gen_rand() -> Self {
        unsafe {
            let mut boxed = SodiumBox::new_with_size(Self::SIZE);

            randombytes_buf(boxed.as_mut_ptr(), Self::SIZE);

            Self {
                inner: boxed.cast(),
            }
        }
    }
    pub fn from_raw(src: *const u8) -> Self {
        let boxed = SodiumBox::from_raw(src, Self::SIZE);
        Self { inner: boxed }
    }
    fn as_ptr(&self) -> *const u8 {
        self.inner.as_ptr()
    }
    pub fn zeroize(&mut self) {
    }
    pub fn copy_to(&self, ptr: *mut u8) {
        self.inner.copy_to(ptr)
    }
}

pub const ECIES_SHARED_SECRET_SIZE: usize = 32;
pub struct SharedSecret {
    inner: SodiumBox<u8>,
}
impl SharedSecret {
    const SIZE: usize = ECIES_SHARED_SECRET_SIZE;
    pub fn from_sk_pk(sk: &SecKey, pk: &PubKey) -> Self {
        unsafe {
            let mut boxed = SodiumBox::new_with_size(Self::SIZE);

            let rc = crypto_scalarmult(boxed.as_mut_ptr(), sk.as_ptr(), pk.as_ptr());
            assert_eq!(rc, 0);

            Self { inner: boxed }
        }
    }
    fn as_ptr(&self) -> *const u8 {
        self.inner.as_ptr()
    }
}
pub fn shared_secret_to_aes_key(shared: &SharedSecret) -> AesKey {
    let halo = &[
        95u8, 213, 252, 194, 137, 54, 67, 46, 29, 206, 72, 249, 3, 152, 242, 90, 219, 64, 130,
        21, 7, 96, 24, 187, 85, 69, 81, 233, 218, 40, 105, 233,
    ];
    let mut hasher = Blake2b::<{ AES_KEY_SIZE }>::new();
    hasher.update(halo);
    hasher.update_from_ptr(shared.as_ptr(), ECIES_SHARED_SECRET_SIZE);
    let mut boxed = SodiumBox::new_with_size(AES_KEY_SIZE);
    hasher.finalize_write_to(boxed.as_mut_ptr());
    AesKey::from_sodium_box(boxed)
}
