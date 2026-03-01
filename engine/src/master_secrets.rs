use crate::{manual_zeroize, user_secrets};
use crate::header::{Salt};
use crate::user_secrets::{wrap_user_key, UserKey, UserKeyNonce, WrappedUserKey};
use argon2::password_hash::rand_core;
use argon2::{Argon2, Params};
use rand_core::OsRng;
use rand_core::RngCore;
use std::ptr;
use rkyv::rancor::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};
use crate::data_base::{change_user_pw, get_user_pw, DBIOError, DB};
use std::fmt::{Display, Formatter};
use std::error::Error as StdError;
use std::ffi::c_uchar;
use aes_gcm::{Aes256Gcm, KeyInit};
use aes_gcm::aead::Aead;
use libsodium_sys as sodium;
use libsodium_sys::*;
use secrecy::{ExposeSecret, ExposeSecretMut, SecretBox};

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum MasterPWError {
    // 생성
    Empty,
    TooShort,
    ContainsWhitespace,

    // 로그인
    IncorrectPW,

    // 프로세스 유효성
    InvalidSession
}
pub fn master_pw_validation(raw_pw: &String) -> Result<(), MasterPWError> {

    if raw_pw.is_empty() {
        return Err(MasterPWError::Empty);
    }
    if raw_pw.len() < 8 {
        return Err(MasterPWError::TooShort);
    }
    if raw_pw.chars().any(|c| c.is_whitespace()) {
    }

    Ok( () )
}

impl Display for MasterPWError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            MasterPWError::Empty => {
                write!(f, "Empty")
            }
            MasterPWError::TooShort => {
                write!(f, "TooShort")
            }
            MasterPWError::ContainsWhitespace => {
                write!(f, "ContainsWhitespace")
            }
            MasterPWError::IncorrectPW => {
                write!(f, "IncorrectPW")
            }
            MasterPWError::InvalidSession => {
                write!(f, "InvalidSession")
            }
        }
    }
}

impl StdError for MasterPWError {}


#[inline]
fn get_wrapped_user_key(sec_key: &SecKey) -> (WrappedUserKey, UserKeyNonce) {
    let halo = [40u8, 167, 39, 179, 72, 65, 122, 230, 190, 236, 125, 99, 81, 178, 50, 71, 35, 205, 141, 170, 74, 54, 227, 7, 92, 208, 212, 206, 126, 216, 55, 37];

    let params = Params::new(
        64*1024,// 메모리 요구량 (KB 단위)
        1,       // 반복 횟수
        6,      // 병렬 처리 수준
        Some(32),     // 출력 길이f
    ).unwrap();
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        params
    );

    let mut user_key = UserKey::new();
    argon2
        .hash_password_into(&sec_key.as_slice(), &halo, user_key.as_mut_bytes())
        .unwrap();

    wrap_user_key(user_key)
}

fn master_pw_kdf(master_pw: &String, salt: &Salt) -> SecKey {
    let params = Params::new(
        128*1024, // 메모리 요구량 (KB 단위)
        1,         // 반복 횟수
        12,       // 병렬 처리 수준
        Some(32),       // 출력 길이
    ).unwrap();
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        params
    );
    let mut kdf_out = [0u8; 32];
    argon2.hash_password_into(
        master_pw.as_bytes(), salt,
        kdf_out.as_mut()
    ).unwrap();
    let sec_key = SecKey::from_array(kdf_out);
    kdf_out.zeroize();
    sec_key
}


pub fn general_login(master_pw: &mut String, salt: &Salt)
                     -> Result<(SecKey, PubKey, WrappedUserKey, UserKeyNonce), MasterPWError> {
    let mut sec_key = master_pw_kdf(master_pw, salt);
    master_pw.zeroize();
    let pub_key = PubKey::from_sec_key(&sec_key);
    let (wrapped_user_key, user_key_nonce) = get_wrapped_user_key(&sec_key);
    Ok( (sec_key, pub_key, wrapped_user_key, user_key_nonce) )
}
pub fn first_login(mut master_pw: String) -> (PubKey, Salt, WrappedUserKey, UserKeyNonce) {
    let mut salt = Salt::default();
        OsRng.fill_bytes(salt.as_mut_slice());
        let sec_key = master_pw_kdf(&master_pw, &salt);

    master_pw.zeroize();

    let pub_key = PubKey::from_sec_key(&sec_key);
    let (wrapped_user_key, user_key_noce) = get_wrapped_user_key(&sec_key);
    drop(sec_key);

    (pub_key, salt, wrapped_user_key, user_key_noce)
}
pub fn change_master_pw(db: &mut DB, mut new_master_pw: String, wrapped_user_key: &mut WrappedUserKey, user_key_nonce: &mut UserKeyNonce)
                        -> Result<(PubKey, Salt), MasterPWError> {
    let mut salt = Salt::default();
    OsRng.fill_bytes(salt.as_mut_slice());
    let sec_key = master_pw_kdf(&new_master_pw, &salt);

    new_master_pw.zeroize();

    let mut pub_key = PubKey::from_sec_key(&sec_key);
    let (new_wrapped_user_key, new_user_key_nonce) = get_wrapped_user_key(&sec_key);
    drop(sec_key);

    let mut users_archive = vec![];
    for site in &mut *db {
        for user in site.1 {

            users_archive.push((site.0.clone(), user.0.clone()));
        }
    }

    for user in users_archive.into_iter() {

        let user_pw = get_user_pw(&db, &user.0, &user.1, &wrapped_user_key, &user_key_nonce).unwrap();

        if let Err(_) = change_user_pw(&mut *db, &user.0, &user.1, user_pw, &new_wrapped_user_key, &new_user_key_nonce) {
            drop(pub_key);
            drop(new_wrapped_user_key);
            drop(new_user_key_nonce);
            return Err(MasterPWError::InvalidSession);
        }
    }

    wrapped_user_key.zeroize();
    *wrapped_user_key = new_wrapped_user_key;
    user_key_nonce.zeroize();
    *user_key_nonce = new_user_key_nonce;
    Ok( (pub_key, salt) )
}




const AES_NONCE_BEGIN: usize = ECIES_PK_SIZE;
const AES_NONCE_END: usize = AES_NONCE_BEGIN + AES_NONCE_SIZE;
const CIPHERTEXT_BEGIN: usize = AES_NONCE_END.next_power_of_two();

pub type EncryptedDB = Vec<u8>;

pub fn encrypt_db(db: &DB, pk: &PubKey,) -> EncryptedDB {
    let mut serialized = rkyv::to_bytes::<Error>(db).unwrap();

    let peer_sk = SecKey::gen_rand();
    let shared = SharedSecret::from_sk_pk(&peer_sk, &pk);
    let once_aes_key = AesKey::from_shared_secret(&shared);
    drop(shared);
    let peer_pk = PubKey::from_sec_key(&peer_sk);
    drop(peer_sk);

    let cipher = Aes256Gcm::new_from_slice(once_aes_key.as_slice()).unwrap();
    let nonce = AesNonce::gen_rand();
    let ciphertext =
        cipher
            .encrypt(aes_gcm::Nonce::from_slice(nonce.as_slice()), &*serialized).unwrap();
    let mut result = vec![0u8; CIPHERTEXT_BEGIN + ciphertext.len()];
    result[..AES_NONCE_BEGIN].copy_from_slice(peer_pk.as_slice());
    result[AES_NONCE_BEGIN..AES_NONCE_END].copy_from_slice(nonce.as_slice());
    result[CIPHERTEXT_BEGIN..].copy_from_slice(ciphertext.as_slice());
    result
}

pub fn decrypt_db(bytes: &Vec<u8>, sk: SecKey) -> Result<DB, MasterPWError> {
    let peer_pk = &bytes[..AES_NONCE_BEGIN];
    let nonce = &bytes[AES_NONCE_BEGIN..AES_NONCE_END];
    let ciphertext = &bytes[CIPHERTEXT_BEGIN..];

    let shared = SharedSecret::from_sk_pk(&sk, &PubKey::from_slice(peer_pk));
    drop(sk);
    let once_aes_key = AesKey::from_shared_secret(&shared);

    let cipher = Aes256Gcm::new_from_slice(once_aes_key.as_slice()).unwrap();
;    let nonce = aes_gcm::Nonce::from_slice(nonce);
    let mut plaintext =
        cipher
            .decrypt(&nonce, ciphertext)
            .map_err(|_| MasterPWError::IncorrectPW)?;
    drop(once_aes_key);
    let db = rkyv::from_bytes::<DB, Error>(&plaintext).unwrap();
    plaintext.zeroize();

    Ok( db )
}


pub fn __manual_zeroize<T>(data: &mut T) {
    let size = std::mem::size_of::<T>();
    let ptr = data as *mut T as *mut u8;
    unsafe {
        for i in 0..size {
            ptr::write_volatile(ptr.add(i), 0);
        }
    }
}
#[macro_export]
macro_rules! manual_zeroize {
    ($($var:expr),+ $(,)?) => {
        $(
            __manual_zeroize(&mut $var);
        )+
    };
}
