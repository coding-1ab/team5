use crate::master_secrets::static_type_zeroize;
use rkyv::with::{ArchiveWith, DeserializeWith, SerializeWith};
use sha3::{Digest};
use std::cell::RefCell;
use crossbeam_utils::atomic::AtomicCell;
use crate::data_base::{DBIOError, SiteName, UserID, UserPW};
use crate::manual_zeroize;
use argon2::{Argon2, Params};
use std::{hint, process};
use rand::rngs::OsRng;
use sysinfo::{CpuExt, Pid, PidExt, ProcessExt, System, SystemExt};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};
use rkyv::{Archive, Archived, Deserialize, Place, Serialize};
use rkyv::rancor::Fallible;
use rkyv::vec::{ArchivedVec, VecResolver};
use secrecy::{ExposeSecret, ExposeSecretMut, SecretBox};
use sha3::digest::generic_array::GenericArray;
use sha3::Sha3_256;
use libsodium_sys::rust_wrappings::aes256gcm::{aes256gcm_decrypt, aes256gcm_decrypt_from_ptr, aes256gcm_encrypt, aes256gcm_encrypt_from_ptr_to_sodium_box, AesKey, AesNonce, AES_KEY_SIZE, AES_NONCE_SIZE, AES_OUT_AUTH_TAG_SIZE};
use libsodium_sys::rust_wrappings::hasher::Sha256;
use libsodium_sys::rust_wrappings::sodium_box::SodiumBox;

struct SecretBoxRef;

impl ArchiveWith<SecretBox<[u8]>> for SecretBoxRef {
    type Archived = Archived<Vec<u8>>;
    type Resolver = VecResolver;

    fn resolve_with(field: &SecretBox<[u8]>, resolver: Self::Resolver, out: Place<Self::Archived>) {
        let exposed = field.expose_secret();
        ArchivedVec::resolve_from_slice(exposed, resolver, out);
    }
}
impl<S: Fallible + ?Sized> SerializeWith<SecretBox<[u8]>, S> for SecretBoxRef
where
    S: rkyv::ser::Writer + rkyv::ser::Allocator,
{
    fn serialize_with(field: &SecretBox<[u8]>, serializer: &mut S) -> Result<Self::Resolver, S::Error> {
        let exposed = field.expose_secret();
        ArchivedVec::serialize_from_slice(exposed, serializer)
    }
}
impl<D: Fallible + ?Sized> DeserializeWith<Archived<Vec<u8>>, SecretBox<[u8]>, D> for SecretBoxRef {
    fn deserialize_with(field: &Archived<Vec<u8>>, _deserializer: &mut D) -> Result<SecretBox<[u8]>, D::Error> {
        Ok(SecretBox::new(field.as_slice().into()))
    }
}

#[derive(Archive, Deserialize, Serialize)]
pub struct EncryptedSiteName {
    #[rkyv(with = SecretBoxRef)]
    full: SecretBox<[u8] >,
    #[rkyv(with = SecretBoxRef)]
    reg: SecretBox<[u8] >,
}
impl EncryptedSiteName {
    pub fn full_as_bytes(&self) -> &[u8] {
        self.full.expose_secret().as_ref()
    }
    pub fn reg_as_bytes(&self) -> &[u8] {
        self.reg.expose_secret().as_ref()
    }
}
impl Zeroize for EncryptedSiteName {
    fn zeroize(&mut self) {
        self.full.zeroize();
        self.reg.zeroize();
    }
}
impl ZeroizeOnDrop for EncryptedSiteName {}

#[derive(Archive, Deserialize, Serialize)]
pub struct EncryptedUserID (
    #[rkyv(with = SecretBoxRef)]
    SecretBox<[u8]>,
);
impl EncryptedUserID {
    pub fn as_bytes(&self) -> &[u8] {
        self.0.expose_secret().as_ref()
    }
}
impl Zeroize for EncryptedUserID {
    fn zeroize(&mut self) {
        self.0.zeroize()
    }
}
impl ZeroizeOnDrop for EncryptedUserID {}

#[derive(Archive, Deserialize, Serialize)]
pub struct EncryptedUserPW (
    #[rkyv(with = SecretBoxRef)]
    SecretBox<[u8]>,
);
impl EncryptedUserPW {
    pub fn from_vec(mut v: Vec<u8>) -> Self {
        let secret_boxed = SecretBox::from(Box::from(v));
        EncryptedUserPW(secret_boxed)
    }
    pub fn as_bytes(&self) -> &[u8] {
        self.0.expose_secret().as_ref()
    }
}
impl Zeroize for EncryptedUserPW {
    fn zeroize(&mut self) {
        self.0.zeroize()
    }
}
impl ZeroizeOnDrop for EncryptedUserPW {}


const USER_PW_NONCE_SIZE: usize = AES_NONCE_SIZE;
pub struct UserPWNonce {
    inner: AesNonce,
}
impl UserPWNonce {
    pub fn gen_rand() -> Self {
        Self {inner: AesNonce::gen_rand()}
    }
    pub fn from_raw(src: *const u8) -> Self {
        let nonce = AesNonce::from_raw(src);
        Self {inner: nonce}
    }
    pub fn copy_to(&self, dst: *mut u8) {
        self.inner.copy_to(dst)
    }
    // pub fn as_bytes(&self) -> &[u8] {
    //     self.0.expose_secret().as_slice()
    // }
    // pub fn as_mut_bytes(&mut self) -> &mut [u8] {
    //     self.0.expose_secret_mut().as_mut_slice()
    // }
    // pub fn as_ptr(&self) -> *const u8 {
    //     self.0.expose_secret().as_ptr()
    // }
}
impl Default for UserPWNonce {
    fn default() -> Self {
        Self {inner: AesNonce::default()}
    }
}
impl Into<AesNonce> for UserPWNonce {
    fn into(self) -> AesNonce {
        self.inner
    }
}

const SESSION_KEY_NONCE_SIZE: usize = AES_NONCE_SIZE;
pub struct SessionKeyNonce {
    inner: AesNonce,
}
impl SessionKeyNonce {
    pub fn gen_rand() -> Self {
        Self {inner: AesNonce::gen_rand(), }
    }
    // pub fn as_array(&self) -> [u8; _] {
    //     *self.0.expose_secret()
    // }
    // pub fn as_bytes(&self) -> &[u8] {
    //     self.0.expose_secret().as_slice()
    // }
    // pub fn as_mut_bytes(&mut self) -> &mut [u8] {
    //     self.0.as_mut_slice()
    // }
    // pub fn as_ptr(&self) -> *const u8 {
    //     self.0.expose_secret().as_ptr()
    // }
}
impl Into<AesNonce> for SessionKeyNonce {
    fn into(self) -> AesNonce {
        self.inner
    }
}
impl AsRef<AesNonce> for SessionKeyNonce {
    fn as_ref(&self) -> &AesNonce {
        &self.inner
    }
}
impl Zeroize for SessionKeyNonce {
    fn zeroize(&mut self) {
        self.inner.zeroize()
    }
}

const SESSION_KEY_WRAPPER_SIZE: usize = AES_KEY_SIZE;
pub struct SessionKeyWrapper {
    inner: AesKey,
}
impl SessionKeyWrapper {
    fn as_mut_ptr(&mut self) -> *mut u8 {
        self.inner.as_mut_ptr()
    }
    // pub fn as_array(&self) -> [u8; _] {
    //     *self.0.expose_secret()
    // }
    // pub fn as_bytes(&self) -> &[u8] {
    //     self.0.expose_secret().as_slice()
    // }
    // pub fn as_mut_bytes(&mut self) -> &mut [u8] {
    //     self.0.expose_secret_mut().as_mut_slice()
    // }
}
impl Default for SessionKeyWrapper {
    fn default() -> Self {
        Self {inner: AesKey::default()}
    }
}
impl Into<AesKey> for SessionKeyWrapper {
    fn into(self) -> AesKey {
        self.inner
    }
}

const WRAPPED_SESSION_KEY_SIZE: usize = AES_KEY_SIZE + AES_OUT_AUTH_TAG_SIZE;
pub struct WrappedSessionKey {
    inner: SodiumBox<u8>,
}
impl WrappedSessionKey {
    const SIZE: usize = WRAPPED_SESSION_KEY_SIZE;
    fn from_sodium_box(sodium_box: SodiumBox<u8>) -> Self {
        Self {inner: sodium_box}
    }
    pub fn as_ptr(&self) -> *const u8 {
        self.inner.as_ptr()
    }
}
impl Zeroize for WrappedSessionKey {
    fn zeroize(&mut self) {
        self.inner.zeroize()
    }
}

pub const SESSION_KEY_SIZE: usize = 32;
pub struct SessionKey {
    inner: SodiumBox<u8>,
}
impl SessionKey {
    const SIZE: usize = SESSION_KEY_SIZE;
    pub fn gen_rand() -> Self {
        Self {inner: SodiumBox::new_with_size(Self::SIZE)}
    }
    fn from_sodium_box(sodium_box: SodiumBox<u8>) -> Self {
        Self {inner: sodium_box}
    }
    pub fn from_raw(src: *const u8) -> Self {
        Self {inner: SodiumBox::from_raw(src, Self::SIZE)}
    }
    pub fn as_ptr(&self) -> *const u8 {
        self.inner.as_ptr()
    }
    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.inner.as_mut_ptr()
    }
    pub fn copy_to(&self, dst: *mut u8) {
        self.inner.copy_to(dst)
    }
}
impl Into<AesKey> for SessionKey {
    fn into(self) -> AesKey {
        AesKey::from_sodium_box(self.inner)
    }
}
impl Default for SessionKey {
    fn default() -> Self {
        Self {inner: SodiumBox::new_with_size(Self::SIZE)}
    }
}


pub fn get_session_key_wrapper() -> SessionKeyWrapper {
    let mut hasher: Sha256 = Sha256::new();;
    hasher.update(&[248, 106, 27, 141, 130, 70, 18, 189, 65, 15, 132, 220, 144, 144, 143, 196, 57, 128, 134, 145, 197, 235, 192, 209, 150, 152, 201, 113, 12, 189, 100, 93, 92, 69, 244, 146, 157, 57, 131, 56, 143, 160, 17, 233, 114, 23, 32, 13, 68, 9, 116, 95, 26, 104, 73, 81, 7, 7, 103, 206, 63, 251, 161, 223, 226, 125, 184, 225, 6, 164, 65, 13]);
    let mut sys = System::new();
    sys.refresh_all();

    let mut pid_u32 = process::id();
    let mut s_pid = Pid::from_u32(pid_u32);
    let mut ppid = sys.process(s_pid)
        .and_then(|p| p.parent())
        .map(|p| p.as_u32()).unwrap();
    let mut combined_pids = (pid_u32 as u64) << 32 | (ppid as u64);
    pid_u32.zeroize();
    ppid.zeroize();
    hasher.update(&combined_pids.to_ne_bytes());
    combined_pids.zeroize();

    let mut start_time = sys.process(s_pid)
        .map(|p| p.start_time()).unwrap();
    combined_pids.zeroize();
    manual_zeroize!(s_pid);
    hasher.update(&start_time.to_ne_bytes());
    start_time.zeroize();

    // let mut host_name = System::host_name().unwrap_or_else(|| "/\'&%unknown".into());
    // hasher.update(host_name.as_bytes());
    // host_name.zeroize();
    // let mut kernel_version = System::kernel_version().unwrap_or_else(|| "?\"$unknown".into());
    // hasher.update(kernel_version.as_bytes());
    // kernel_version.zeroize();
    //
    // let mut user_name = whoami::username();
    // hasher.update(user_name.as_bytes());
    // user_name.zeroize();

    let cpu_model = sys.global_cpu_info().brand();
    hasher.update(cpu_model.as_bytes());

    // let system_id = get_hwid().unwrap();
    // let disk_id = get_disk_id().unwrap();
    // let nic_mac = get_mac_address().unwrap();

    // sys.zeroize();

    let mut result = SessionKeyWrapper::default();
    hasher.finalize_write_to(result.as_mut_ptr());

    result
}

#[inline]
fn get_user_pw_nonce(site: &SiteName, id: &UserID)
    -> UserPWNonce {
    let mut processed_id = id.as_str().to_owned().into_bytes();
    let halo = [203u8, 118, 6, 1, 225, 226, 197, 127, 221, 214, 24, 5, 239, 38, 75, 82, 65, 111, 91, 110, 158, 25, 48, 178, 116, 137, 136, 49, 57, 192, 56, 52];

    for (t, s) in processed_id.iter_mut().zip(site.as_str().as_bytes().iter()) {
        *t ^= *s;
    }

    let params = Params::new(
        32*1024, // 메모리 요구량 (KB 단위)
        1,        // 반복 횟수
        2,       // 병렬 처리 수준
        Some(12),      // 출력 길이
    ).unwrap();
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        params
    );

    let mut rust_owned_nonce = [0u8; USER_PW_NONCE_SIZE];
    hint::black_box(rust_owned_nonce.as_mut_ptr());
    argon2
        .hash_password_into(&processed_id, &halo, rust_owned_nonce.as_mut_slice())
        .unwrap();
    let nonce = UserPWNonce::from_raw(rust_owned_nonce.as_ptr());
    processed_id.zeroize();
    rust_owned_nonce.zeroize();

    nonce
}


pub fn wrap_session_key(session_key: SessionKey)
                        -> (WrappedSessionKey, SessionKeyNonce) {
    let wrapper = get_session_key_wrapper().into();
    let nonce = SessionKeyNonce::gen_rand();

    let ciphertext =
        aes256gcm_encrypt_from_ptr_to_sodium_box(&wrapper, nonce.as_ref(), session_key.as_ptr(), SESSION_KEY_SIZE);
    drop(wrapper);
    drop(session_key);
    let wrapped_key = WrappedSessionKey::from_sodium_box(ciphertext);

    (wrapped_key, nonce)
}

#[inline(always)]
pub fn unwrap_session_key(wrapped_key: &WrappedSessionKey, nonce: &SessionKeyNonce)
                          -> Result<SessionKey, DBIOError> {
    let wrapper = get_session_key_wrapper().into();
    let plaintext =
        aes256gcm_decrypt_from_ptr(&wrapper, nonce.as_ref(), wrapped_key.as_ptr(), WRAPPED_SESSION_KEY_SIZE)
            .map_err(|_| DBIOError::InvalidSession)?;
    let session_key = SessionKey::from_sodium_box(plaintext);
    Ok(session_key)
}

//todo
pub fn encrypt_user_pw(site: &SiteName, id: &UserID, user_pw: UserPW, wrapped_key: &WrappedSessionKey, user_key_nonce: &SessionKeyNonce)
                       -> Result<EncryptedUserPW, DBIOError> {
    let session_key: AesKey = unwrap_session_key(wrapped_key, user_key_nonce)?.into();
    let user_pw_nonce: AesNonce = get_user_pw_nonce(site, id).into();
    let ciphertext =
        aes256gcm_encrypt(&session_key, &user_pw_nonce, user_pw.as_str().as_bytes());
    drop(session_key);
    drop(user_pw_nonce);
    let encrypted_pw = EncryptedUserPW::from_vec(ciphertext);

    Ok( encrypted_pw )
}

#[inline(always)]
pub fn decrypt_user_pw(site: &SiteName, id: &UserID, encrypted_pw: &EncryptedUserPW, wrapped_key: &WrappedSessionKey, user_key_nonce: &SessionKeyNonce)
                       -> Result<UserPW, DBIOError> {
    let user_key: AesKey = unwrap_session_key(wrapped_key, user_key_nonce)?.into();
    let user_pw_nonce: AesNonce = get_user_pw_nonce(site, id).into();
    let plaintext =
        aes256gcm_decrypt(&user_key, &user_pw_nonce, encrypted_pw.as_bytes())
            .map_err(|_| DBIOError::InvalidSession)?
            .into();
    drop(user_key);
    drop(user_pw_nonce);

    let user_pw = UserPW::from_unchecked(
        String::from_utf8(plaintext).unwrap()
    );

    Ok( user_pw )
}
