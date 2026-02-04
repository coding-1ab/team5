use crate::data_base::{DBIOError, SiteName, UserID, UserPW};
use crate::master_secrets::{AesKey, __manual_zeroize};
use crate::manual_zeroize;
use aes_gcm::aead::{Aead, Nonce, OsRng};
use aes_gcm::{AeadCore, Aes256Gcm, Key, KeyInit};
use argon2::{Argon2, ParamsBuilder};
use sha2::digest::generic_array::{arr, GenericArray};
use sha2::{Digest, Sha256};
use std::process;
use std::sync::OnceLock;
use aes_gcm::aes::Aes256;
use log::debug;
use sysinfo::{Pid, System};
use zeroize::{Zeroize, Zeroizing};


/// 명시적 zeroize로 변경하기
/// 종료전 유효성 검사
pub const MAX_USER_PW_LEN: usize = 32;
pub type EncryptdUsrPW = Vec<u8>;
pub type UserPWNonce = Box<[u8; 12]>;
pub type UserKeyWrapper = Box<[u8; 32]>;
pub type WrappedUserKey = Vec<u8>;
pub type UserKey = Box<[u8; 32]>;
pub fn get_system_identity() -> Box<[u8; 32]> {
    let mut hasher = Sha256::new();

    let mut sys = System::new();
    sys.refresh_all();

    let mut pid_u32 = process::id();
    let mut s_pid = Pid::from(pid_u32 as usize);
    let mut ppid = sys.process(s_pid)
        .and_then(|p| p.parent())
        .map(|p| p.as_u32())
        .unwrap_or(0);
    let mut combined_pid = (pid_u32 as u64) << 32 | (ppid as u64);
    manual_zeroize!(pid_u32, s_pid, ppid);
    hasher.update(&combined_pid.to_le_bytes());
    combined_pid.zeroize();

    let mut start_time = sys.process(s_pid)
        .map(|p| p.start_time())
        .unwrap_or(0);
    hasher.update(&start_time.to_le_bytes());
    start_time.zeroize();

    let mut host_name = System::host_name().unwrap_or_else(|| "/\'&%unknown".into());
    hasher.update(&host_name);
    host_name.zeroize();
    let mut kernel_version = System::kernel_version().unwrap_or_else(|| "?\"$unknown".into());
    hasher.update(&kernel_version);
    kernel_version.zeroize();

    let mut total_memory = sys.total_memory();
    let mut total_processors = sys.physical_core_count();
    let mut combined_c = total_memory as usize + total_processors.unwrap_or(4);
    manual_zeroize!(total_memory, total_processors);
    hasher.update(combined_c.to_le_bytes());
    combined_c.zeroize();

    let mut result = UserKeyWrapper::default();
    hasher.finalize_into_reset(GenericArray::from_mut_slice(result.as_mut_slice()));
    result
}
fn get_user_pw_nonce(site: &SiteName, id: &UserID) -> UserPWNonce {
    let mut hasher1 = Sha256::new();
    hasher1.update(format!("`*!^{}{}",id.as_str(), site.as_str()).as_bytes());
    let mut hasher2 = hasher1.clone();
    let mut salt= [0u8; 32];
    hasher1.finalize_into_reset(GenericArray::from_mut_slice(salt.as_mut_slice()));
    hasher2.update(format!("{}\\@#{}", id.as_str(), site.as_str()).as_bytes());
    let mut source = [0u8; 32];
    hasher2.finalize_into_reset(GenericArray::from_mut_slice(source.as_mut_slice()));
    let params = ParamsBuilder::new()
        .m_cost(16384) // 16MB 지정 (KB 단위)
        .t_cost(3)     // 반복 횟수
        .p_cost(3)     // 병렬 처리 수준
        .output_len(12)
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
// fn is_valid_nonce(nonce: &Nonce<Aes256Gcm>) -> bool {
//     let first_byte = nonce[0];
//     let is_printable_ascii = first_byte >= 0x20 && first_byte <= 0x7E;
//     let is_safe_control = first_byte == 0x09;
//     is_printable_ascii || is_safe_control
// }
// fn gen_valid_nonce() -> Nonce<Aes256Gcm> {
//     let mut candidate;
//     loop {
//         candidate = Aes256Gcm::generate_nonce(&mut OsRng);
//         if is_valid_nonce(&candidate) {
//             return candidate;
//         }
//     }
// }
static USER_KEY_NONCE: OnceLock<Nonce<Aes256Gcm>> = OnceLock::new();
pub fn wrap_user_key(mut user_key: UserKey)
                     -> Result<WrappedUserKey, DBIOError> {
    let mut wrapper = get_system_identity();
    let nonce = USER_KEY_NONCE
        .get_or_init(|| Aes256Gcm::generate_nonce(OsRng));
    let cipher = Aes256Gcm::new_from_slice(wrapper.as_slice())
        .map_err(|_| DBIOError::InvalidSession)?;
    let ciphertext =
        cipher
            .encrypt(nonce, user_key.as_slice())
            .map_err(|_| DBIOError::InvalidSession)?;
    wrapper.zeroize();
    user_key.zeroize();
    Ok( ciphertext )
}

pub fn unwrap_user_key(wrapped_key: &WrappedUserKey)
                          -> Result<UserKey, DBIOError> {
    let mut wrapper = get_system_identity();
    let cipher = Aes256Gcm::new_from_slice(wrapper.as_slice())
        .map_err(|_| DBIOError::InvalidSession)?;
    let nonce = USER_KEY_NONCE
        .get_or_init(|| Aes256Gcm::generate_nonce(OsRng));
    let plaintext =
        cipher
        .decrypt(nonce, wrapped_key.as_slice())
        .map_err(|_| DBIOError::InvalidSession)?;
    let user_key: UserKey = plaintext.try_into()
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
                      -> Result<EncryptdUsrPW, DBIOError> {
    let mut nonce = get_user_pw_nonce(&site, &id);
    let mut user_key = unwrap_user_key(&wrapped_key)?;
    let cipher = Aes256Gcm::new_from_slice(user_key.as_mut_slice())
        .map_err(|_| DBIOError::InvalidSession)?;
    debug!("\n1\n");
    let ciphertext =
        cipher
            .encrypt(aes_gcm::Nonce::from_slice(nonce.as_slice()), user_pw.as_str().as_bytes())
            .map_err(|_| DBIOError::InvalidSession)?;
    debug!("\n2\n");
    user_key.zeroize();
    nonce.zeroize();
    Ok( ciphertext )
}

pub fn decrypt_user_pw(site: &SiteName, id: &UserID, encrypted_pw: &EncryptdUsrPW, wrapped_key: &WrappedUserKey)
                       -> Result<UserPW, DBIOError> {
    let mut nonce = get_user_pw_nonce(&site, &id);
    let mut user_key = unwrap_user_key(&wrapped_key)?;
    let cipher = Aes256Gcm::new_from_slice(user_key.as_slice())
        .map_err(|_| DBIOError::InvalidSession)?;
    let plaintext =
        cipher
        .decrypt(aes_gcm::Nonce::from_slice(nonce.as_slice()), encrypted_pw.as_slice())
        .map_err(|_| DBIOError::InvalidSession)?;
    user_key.zeroize();
    nonce.zeroize();
    let user_pw = UserPW::from_uncheched(
        String::from_utf8(plaintext)
            .map_err(|_| DBIOError::InvalidSession)?
    );
    Ok( user_pw )
}
