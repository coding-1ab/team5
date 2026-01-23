use sysinfo::{Pid, System};
use std::process;
use std::string::FromUtf8Error;
use aes_gcm::{AeadCore, Aes256Gcm, KeyInit};
use aes_gcm::aead::{Aead, Nonce, OsRng};
use eframe::egui::text_selection::visuals::paint_cursor_end;
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::SeedableRng;
use sha2::{Sha256, Digest};
use zeroize::{Zeroize, Zeroizing};
use crate::crypto::CryptoError;
use crate::data_base::{SiteName, UserID, UserPW, DB};
use crate::ZeroizingString;

enum UserCryptoError { // 보안상 의도적으로 unwrap과 decrypto 시에 공통으로 사용
    InvalidKey,
    EncryptionFailed,
    DecryptionFailed
}

pub const MAX_USER_PW_LEN: usize = 32;
// pub type EncUserPW = (Zeroizing<Nonce<Aes256Gcm>>, Zeroizing<Vec<u8>>);
// pub type UserKeyWrapper = Zeroizing<[u8; 32]>;
// pub type WrappedUserKey = Zeroizing<Vec<u8>>;
// pub type UserKey = Zeroizing<[u8; 32]>;
//TODO 명시적 Zeroizing 호출로 변경하기

fn get_system_identity() -> UserKeyWrapper {
    let mut sys = System::new();
    sys.refresh_processes();

    let pid_u32 = process::id();
    let s_pid = Pid::from(pid_u32 as usize);
    let ppid = sys.process(s_pid)
        .and_then(|p| p.parent())
        .map(|p| p.as_u32())
        .unwrap_or(0);
    let boot_time = System::boot_time();
    let start_time = sys.process(s_pid)
        .map(|p| p.start_time())
        .unwrap_or(0);

    let hostname = System::host_name().unwrap_or_else(|| "/\'&%unknown".into());
    let kernel_version = System::kernel_version().unwrap_or_else(|| "?\"$unknown".into());
    let total_memory = sys.total_memory();
    let total_processors = sys.physical_core_count();

    let mut hasher = Sha256::new();
    hasher.update(s_pid);
    hasher.update(ppid);
    hasher.update(boot_time);
    hasher.update(start_time);
    hasher.update(hostname);
    hasher.update(kernel_version);
    hasher.update(total_memory);
    hasher.update(total_processors);

    let hash = hasher.finalize();
    let mut result = [0u8;32];
    result.copy_from_slice(&hash);
    Zeroizing::new(result)
}

fn wrap_user_key(user_key: UserKey)
                 -> Result<WrappedUserKey, UserCryptoError> {
    let wrapper = get_system_identity();
    let cipher = Aes256Gcm::new_from_slice(wrapper.as_bytes())
        .map_err(|_| UserCryptoError::InvalidKey)?;
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = Zeroizing::new(
        cipher
            .encrypt(&nonce, user_key.as_ref())
            .map_err(|_| UserCryptoError::EncryptionFailed)?
    );
    Ok( ciphertext )
}

fn unwrap_user_key(wrapped_key: WrappedUserKey)
                   -> Result<UserKey, UserCryptoError> {
    let wrapper = get_system_identity();
    let cipher = Aes256Gcm::new_from_slice(wrapper.as_bytes())
        .map_err(|_| UserCryptoError::InvalidKey)?;
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let plaintext = cipher
        .decrypt(
            aes_gcm::Nonce::from_slice(&nonce.as_bytes()), &wrapped_key
        )
        .map_err(|_| UserCryptoError::DecryptionFailed)?;
    let user_key: UserKey = Zeroizing::new(
        plaintext.try_into()
            .expect(|_| UserCryptoError::DecryptionFailed)
    );
    Ok( user_key )
}

// fn get_user_nonce(site: &SiteName, id: &UserID) -> UserKey {
//     let mut hasher = Sha256::new();
//     hasher.update(&site);
//     hasher.update(&id);
//     hasher.update(site);
//     hasher.update(id);
//     let hash = hasher.finalize();
//     let result = hash.as_slice();
//     Zeroizing::new(result.as_bytes())
// }

pub fn encryt_user_pw(/*site: &SiteName, id: &UserID,*/ user_pw: UserPW, wrapped_key: WrappedUserKey)
                      -> Result<EncUserPW, UserCryptoError> {
    let user_key = unwrap_user_key(wrapped_key)?;
    // let nonce = get_user_nonce(site, id, user_key);
    let cipher = Aes256Gcm::new_from_slice(user_key.as_bytes())
        .map_err(|_| UserCryptoError::InvalidKey)?;
    let nonce = Zeroizing::new(
        Aes256Gcm::generate_nonce(&mut OsRng)
    );
    let ciphertext = Zeroizing::new(
        cipher
            .encrypt(&nonce, user_pw.as_ref())
            .map_err(|_| UserCryptoError::EncryptionFailed)?
    );
    Ok( ((nonce, ciphertext)) )
}

pub fn decrypt_user_pw(site: &SiteName, id: &UserID, encrypted_pw: EncUserPW, wrapped_key: WrappedUserKey)
                       -> Result<UserPW, UserCryptoError> {
    let user_key = unwrap_user_key(wrapped_key)?;
    // let nonce = get_user_nonce(site, id, user_key);
    let cipher = Aes256Gcm::new_from_slice(user_key.as_bytes())
        .map_err(|_| UserCryptoError::InvalidKey)?;
    let plaintext = cipher
        .decrypt(&encrypted_pw.0, &encrypted_pw.1)
        .map_err(|_| UserCryptoError::DecryptionFailed)?;
    let user_pw: UserPW = Zeroizing::new(
        String::from_utf8(plaintext)
            .map_err(|_| UserCryptoError::DecryptionFailed)?
    );
    Ok( user_pw )
}
