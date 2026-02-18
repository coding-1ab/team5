use sha3::{Digest};
use std::cell::RefCell;
use crate::data_base::{DBIOError, SiteName, UserID, UserPW};
use crate::master_secrets::{__manual_zeroize};
use crate::manual_zeroize;
use aes_gcm::aead::{Aead, Nonce, OsRng};
use aes_gcm::{ Aes256Gcm, Key, KeyInit};
use argon2::{Argon2, ParamsBuilder, Params};
use std::process;
use rand::prelude::*;
use sysinfo::{Pid, System};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};
use rkyv::{Archive, Deserialize, Serialize};
use std::pin::Pin;
use sha3::digest::generic_array::GenericArray;
use sha3::digest::Update;
use sha3::Sha3_256;

#[derive(Zeroize, ZeroizeOnDrop)]
#[derive(Archive, Deserialize, Serialize)]
pub struct EncryptedUserPW (Vec<u8>);
impl EncryptedUserPW {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0.as_slice()
    }
}
impl From<Vec<u8>> for EncryptedUserPW {
    fn from(v: Vec<u8>) -> EncryptedUserPW {
        EncryptedUserPW (v)
    }
}
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct UserPWNonce (Box<[u8; 12]>);
impl UserPWNonce {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0.as_slice()
    }
    pub fn as_mut_bytes(&mut self) -> &mut [u8] {
        self.0.as_mut_slice()
    }
}
impl Default for UserPWNonce {
    fn default() -> UserPWNonce {
        UserPWNonce(Box::from([0u8; 12]))
    }
}
#[derive(Zeroize, ZeroizeOnDrop)]
struct UserKeyNonce (Box<[u8; 12]>);
impl UserKeyNonce {
    pub fn new() -> Self {
        let mut boxed = Box::new([0u8; 12]);
        OsRng.fill_bytes(boxed.as_mut_slice());
        UserKeyNonce(boxed)
    }
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }
    // pub fn as_mut_bytes(&mut self) -> &mut [u8] {
    //     self.0.as_mut_slice()
    // }
}
impl Default for UserKeyNonce {
    fn default() -> Self {
        UserKeyNonce(Box::from([0u8; 12]))
    }
}
// impl AsRef<aes_gcm::Nonce<U12>> for UserKeyNonce {
//     fn as_ref(&self) -> &aes_gcm::Nonce<U12> {
//         let array_ref: &[u8; 12] = self.0.as_ref();
//         unsafe {
//             &*(array_ref as *const [u8; 12] as *const aes_gcm::Nonce<U12>)
//         }
//     }
// }
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct UserKeyWrapper (Box<[u8; 32]>);
impl UserKeyWrapper {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0.as_slice()
    }
    pub fn as_mut_bytes(&mut self) -> &mut [u8] {
        self.0.as_mut_slice()
    }
}
impl Default for UserKeyWrapper {
    fn default() -> UserKeyWrapper {
        UserKeyWrapper (Box::new([0u8; _]))
    }
}
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct WrappedUserKey (Vec<u8>);
impl WrappedUserKey {
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }
}
impl From<Vec<u8>> for WrappedUserKey {
    fn from(v: Vec<u8>) -> WrappedUserKey {
        WrappedUserKey(v)
    }
}
impl Default for WrappedUserKey {
    fn default() -> WrappedUserKey {
        WrappedUserKey(Vec::with_capacity(64))
    }
}
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct UserKey (Box<[u8; 32]>);
impl UserKey {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0.as_slice()
    }
    pub fn as_mut_bytes(&mut self) -> &mut [u8] {
        self.0.as_mut_slice()
    }
}
impl From<[u8; 32]> for UserKey {
    fn from(mut arr: [u8; 32]) -> UserKey {
        let key = UserKey ( Box::new(arr) );
        arr.zeroize();
        key
    }
}
impl Default for UserKey {
    fn default() -> Self {
        UserKey (Box::from([0u8; 32]))
    }
}
pub fn get_user_key_wrapper() -> UserKeyWrapper {
    let mut hasher = Sha3_256::new();
    Update::update(&mut hasher, &[248, 106, 27, 141, 130, 70, 18, 189, 65, 15, 132, 220, 144, 144, 143, 196, 57, 128, 134, 145, 197, 235, 192, 209, 150, 152, 201, 113, 12, 189, 100, 93, 92, 69, 244, 146, 157, 57, 131, 56, 143, 160, 17, 233, 114, 23, 32, 13, 68, 9, 116, 95, 26, 104, 73, 81, 7, 7, 103, 206, 63, 251, 161, 223, 226, 125, 184, 225, 6, 164, 65, 13]);
    let mut sys = System::new();
    sys.refresh_all();

    let mut pid_u32 = process::id();
    let mut s_pid = Pid::from(pid_u32 as usize);
    let mut ppid = sys.process(s_pid)
        .and_then(|p| p.parent())
        .map(|p| p.as_u32())
        .unwrap_or(0);
    let mut combined_pids = (pid_u32 as u64) << 32 | (ppid as u64);
    manual_zeroize!(pid_u32, s_pid, ppid);
    Update::update(&mut hasher, &combined_pids.to_le_bytes());

    let mut start_time = sys.process(s_pid)
        .map(|p| p.start_time())
        .unwrap_or(combined_pids);
    combined_pids.zeroize();
    Update::update(&mut hasher, &start_time.to_le_bytes());
    start_time.zeroize();

    let mut host_name = System::host_name().unwrap_or_else(|| "/\'&%unknown".into());
    Update::update(&mut hasher, host_name.as_bytes());
    host_name.zeroize();
    let mut kernel_version = System::kernel_version().unwrap_or_else(|| "?\"$unknown".into());
    Update::update(&mut hasher, kernel_version.as_bytes());
    kernel_version.zeroize();

    let mut total_memory = sys.total_memory();
    let mut total_processors = sys.physical_core_count().unwrap_or(4);
    let mut combined_hw = total_memory as usize + total_processors;
    total_memory.zeroize(); total_processors.zeroize();
    Update::update(&mut hasher, &combined_hw.to_le_bytes());
    combined_hw.zeroize();

    let mut result = UserKeyWrapper::default();
    hasher.finalize_into_reset(GenericArray::from_mut_slice(result.as_mut_bytes()));
    result
}
fn get_user_pw_nonce(site: &SiteName, id: &UserID) -> UserPWNonce {
    let mut processed_id = id.as_str().to_owned().into_bytes();
    let halo = [203u8, 118, 6, 1, 225, 226, 197, 127, 221, 214, 24, 5, 239, 38, 75, 82, 65, 111, 91, 110, 158, 25, 48, 178, 116, 137, 136, 49, 57, 192, 56, 52];

    for (t, s) in processed_id.iter_mut().zip(site.as_str().as_bytes().iter()) {
        *t ^= *s;
    }

    let mut params = Params::new(
        64*1024, // 메모리 요구량 (KB 단위)
        1,        // 반복 횟수
        1,       // 병렬 처리 수준
        Some(12),       // 출력 길이
    ).unwrap();
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        params
    );

    let mut nonce = UserPWNonce::default();
    argon2.hash_password_into(&processed_id, &halo, nonce.as_mut_bytes())
        .unwrap();
    processed_id.zeroize();

    nonce
}


thread_local! {
    static USER_KEY_NONCE: RefCell<UserKeyNonce> = RefCell::new(UserKeyNonce::default());
}

pub fn wrap_user_key(mut user_key: UserKey)
                     -> Result<WrappedUserKey, DBIOError> {
    let mut wrapper = get_user_key_wrapper();
    USER_KEY_NONCE.with_borrow_mut(|v| *v = UserKeyNonce::new());
    let nonce = (USER_KEY_NONCE.with_borrow(|v| *aes_gcm::Nonce::from_slice(v.as_bytes())));
    let cipher = Aes256Gcm::new_from_slice(wrapper.as_bytes())
        .map_err(|_| DBIOError::InvalidSession)?;
    let ciphertext =
        cipher
            .encrypt(&nonce, user_key.as_bytes())
            .map_err(|_| DBIOError::InvalidSession)?;
    wrapper.zeroize();
    user_key.zeroize();

    Ok( ciphertext.into() )
}

pub fn unwrap_user_key(wrapped_key: &WrappedUserKey)
                          -> Result<UserKey, DBIOError> {
    let mut wrapper = get_user_key_wrapper();
    let cipher = Aes256Gcm::new_from_slice(wrapper.as_bytes())
        .map_err(|_| DBIOError::InvalidSession)?;
    let nonce = (USER_KEY_NONCE.with_borrow(|v| *aes_gcm::Nonce::from_slice(v.as_bytes())));
    let plaintext =
        cipher
        .decrypt(&nonce, wrapped_key.as_bytes())
        .map_err(|_| DBIOError::InvalidSession)?;
    let user_key: [u8;32] = plaintext.try_into()
            .map_err(|_| DBIOError::InvalidSession)?;
    wrapper.zeroize();
    Ok( user_key.into() )
}

#[inline(always)]
pub fn encrypt_user_pw(site: &SiteName, id: &UserID, user_pw: UserPW, wrapped_key: &WrappedUserKey)
                       -> Result<EncryptedUserPW, DBIOError> {
    let mut nonce = get_user_pw_nonce(site, id);
    let mut user_key = unwrap_user_key(wrapped_key)?;
    let p_user_key = Pin::new(&mut user_key);
    let cipher = Aes256Gcm::new_from_slice(user_key.as_mut_bytes())
        .map_err(|_| DBIOError::InvalidSession)?;
    let ciphertext =
        cipher
            .encrypt(aes_gcm::Nonce::from_slice(nonce.as_bytes()), user_pw.as_str().as_bytes())
            .map_err(|_| DBIOError::InvalidSession)?;
    user_key.zeroize();
    nonce.zeroize();
    Ok( ciphertext.into() )
}

#[inline(always)]
pub fn decrypt_user_pw(site: &SiteName, id: &UserID, encrypted_pw: &EncryptedUserPW, wrapped_key: &WrappedUserKey)
                       -> Result<UserPW, DBIOError> {
    let mut nonce = get_user_pw_nonce(site, id);
    let mut user_key = unwrap_user_key(wrapped_key)?;
    let cipher = Aes256Gcm::new_from_slice(user_key.as_bytes())
        .map_err(|_| DBIOError::InvalidSession)?;
    let plaintext =
        cipher
        .decrypt(aes_gcm::Nonce::from_slice(nonce.as_bytes()), encrypted_pw.as_bytes())
        .map_err(|_| DBIOError::InvalidSession)?;
    user_key.zeroize();
    nonce.zeroize();
    let user_pw = UserPW::from_unchecked(
        String::from_utf8(plaintext)
            .map_err(|_| DBIOError::InvalidSession)?
    );
    Ok( user_pw )
}
