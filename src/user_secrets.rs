use crate::data_base::{DBIOError, SiteName, UserID, UserPW};
use crate::master_secrets::_manual_zeroize;
use crate::manual_zeroize;
use aes_gcm::aead::{Aead, Nonce, OsRng};
use aes_gcm::{AeadCore, Aes256Gcm, KeyInit};
use argon2::{Argon2, ParamsBuilder};
use sha2::digest::generic_array::GenericArray;
use sha2::{Digest, Sha256};
use std::process;
use std::sync::OnceLock;
use sysinfo::{Pid, System};
use zeroize::Zeroize;


/// 명시적 zeroize로 변경하기
/// 종료전 유효성 검사
pub const MAX_USER_PW_LEN: usize = 32;
pub type EncryptdUsrPW = Vec<u8>;
pub type UserPWNonce = Box<[u8; 32]>;
pub type UserKeyWrapper = Box<[u8; 32]>;
pub type WrappedUserKey = Vec<u8>;
pub type UserKey = Box<[u8; 32]>;
fn get_system_identity() -> UserKeyWrapper {
    let mut sys = System::new();
    sys.refresh_processes();

    let mut pid_u32 = process::id();
    let mut s_pid = Pid::from(pid_u32 as usize);
    let ppid = sys.process(s_pid)
        .and_then(|p| p.parent())
        .map(|p| p.as_u32())
        .unwrap_or(0);
    let mut boot_time = System::boot_time();
    let mut start_time = sys.process(s_pid)
        .map(|p| p.start_time())
        .unwrap_or(0);
    let mut hostname = System::host_name().unwrap_or_else(|| "/\'&%unknown".into());
    let mut kernel_version = System::kernel_version().unwrap_or_else(|| "?\"$unknown".into());
    let mut total_memory = sys.total_memory();
    let mut total_processors = sys.physical_core_count();

    let mut hasher = Sha256::new();
    hasher.update(&s_pid.as_u32().to_le_bytes());
    hasher.update(&ppid.to_le_bytes());
    hasher.update(&boot_time.to_le_bytes());
    hasher.update(&start_time.to_le_bytes());
    hasher.update(&hostname);
    hasher.update(&kernel_version);
    hasher.update(&total_memory.to_le_bytes());
    hasher.update(&total_processors.unwrap_or(4).to_le_bytes());

    let mut result = UserKeyWrapper::default();
    hasher.finalize_into(GenericArray::from_mut_slice(result.as_mut_slice()));
    hostname.zeroize();
    kernel_version.zeroize();
    manual_zeroize!(pid_u32, s_pid, boot_time, start_time,
        total_memory, total_processors);
    result
}
fn get_user_pw_nonce(site: &SiteName, id: &UserID) -> UserPWNonce {
    let mut hasher1 = Sha256::new();
    hasher1.update(format!{"`*!^{}{}",id.0, site.0});
    let mut hasher2 = hasher1.clone();
    let mut salt= [0u8; 32];
    hasher1.finalize_into(GenericArray::from_mut_slice(&mut salt));
    hasher2.update(format!("{}\\@#{}", id.0, site.0));
    let mut source = [0u8; 32];
    hasher2.finalize_into(GenericArray::from_mut_slice(&mut source));
    let params = ParamsBuilder::new()
        .m_cost(16384) // 16MB 지정 (KB 단위)
        .t_cost(3)     // 반복 횟수
        .p_cost(3)     // 병렬 처리 수준
        .build()
        .unwrap();
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        params
    );
    let mut nonce = UserPWNonce::default();
    argon2.hash_password_into(&source, &salt, nonce.as_mut_slice())
        .unwrap();
    manual_zeroize!(source, salt);
    nonce
}
static USER_KEY_NONCE: OnceLock<Nonce<Aes256Gcm>> = OnceLock::new();
pub unsafe fn wrap_user_key(user_key: UserKey)
                        -> Result<WrappedUserKey, DBIOError> {
    let mut wrapper = get_system_identity();
    let nonce = USER_KEY_NONCE
        .get_or_init(|| Aes256Gcm::generate_nonce(&mut OsRng));
    let cipher = Aes256Gcm::new_from_slice(wrapper.as_slice())
        .unwrap();
    let ciphertext =
        cipher
            .encrypt(nonce, user_key.as_slice())
            .map_err(|_| DBIOError::InvalidSession)?;
    wrapper.zeroize();
    Ok( ciphertext )
}

pub unsafe fn unwrap_user_key(wrapped_key: &WrappedUserKey)
                          -> Result<UserKey, DBIOError> {
    let mut wrapper = get_system_identity();
    let cipher = Aes256Gcm::new_from_slice(wrapper.as_slice())
        .unwrap();
    let nonce = USER_KEY_NONCE
        .get_or_init(|| Aes256Gcm::generate_nonce(&mut OsRng));
    let plaintext = cipher
        .decrypt(&nonce, wrapped_key.as_slice())
        .map_err(|_| DBIOError::InvalidSession)?;
    let user_key: UserKey =
        plaintext.try_into()
            .map_err(|_| DBIOError::InvalidSession)?;
    wrapper.zeroize();
    Ok( user_key )
}

// fn get_user_pw_nonce(site: &SiteName, id: &UserID) -> UserKey {
//     let mut hasher = Sha256::new();
//     hasher.update(&site);
//     hasher.update(&id);
//     hasher.update(site);
//     hasher.update(id);
//     let hash = hasher.finalize();
//     let result = hash.as_slice();
//     Zeroizing::new(result.as_bytes())
// }

pub fn encryt_user_pw(site: &SiteName, id: &UserID, user_pw: UserPW, wrapped_key: &WrappedUserKey)
                      -> Result<EncryptdUsrPW,DBIOError> {
    let mut nonce = get_user_pw_nonce(&site, &id);
    let mut user_key = unsafe{ unwrap_user_key(&wrapped_key)? };
    let cipher = Aes256Gcm::new_from_slice(user_key.as_slice())
        .map_err(|_| DBIOError::InvalidSession)?;
    let ciphertext = cipher
            .encrypt(aes_gcm::Nonce::from_slice(nonce.as_slice()), user_pw.0.as_bytes())
            .map_err(|_| DBIOError::InvalidSession)?;
    user_key.zeroize();
    nonce.zeroize();
    Ok( ciphertext )
}

pub fn decrypt_user_pw(site: &SiteName, id: &UserID, encrypted_pw: &EncryptdUsrPW, wrapped_key: &WrappedUserKey)
                       -> Result<UserPW, DBIOError> {
    let mut nonce = get_user_pw_nonce(&site, &id);
    let mut user_key = unsafe{ unwrap_user_key(&wrapped_key)? };
    let cipher = Aes256Gcm::new_from_slice(user_key.as_slice())
        .map_err(|_| DBIOError::InvalidSession)?;
    let plaintext = cipher
        .decrypt(aes_gcm::Nonce::from_slice(nonce.as_slice()), encrypted_pw.as_slice())
        .map_err(|_| DBIOError::InvalidSession)?;
    user_key.zeroize();
    nonce.zeroize();
    let user_pw = UserPW(
        String::from_utf8(plaintext)
            .map_err(|_| DBIOError::InvalidSession)?
    );
    Ok( user_pw )
}
