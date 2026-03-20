use crate::{manual_zeroize, user_secrets};
use crate::header::{Salt};
use crate::user_secrets::{wrap_session_key, SessionKey, SessionKeyNonce, WrappedSessionKey, SESSION_KEY_SIZE};
use argon2::password_hash::rand_core;
use argon2::{Argon2, Params};
use rand_core::OsRng;
use rand_core::RngCore;
use std::{hint, ptr, slice};
use rkyv::rancor::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};
use crate::data_base::{change_user_pw, get_user_pw, DBIOError, DB};
use std::fmt::{Display, Formatter};
use std::error::Error as StdError;
use std::ffi::c_uchar;
use std::io::Write;
use std::ptr::{addr_of, addr_of_mut};
use libsodium_sys as sodium;
use libsodium_sys::*;
use secrecy::{ExposeSecret, ExposeSecretMut, SecretBox};
use libsodium_sys::rust_wrappings::aes256gcm::{aes256gcm_decrypt, aes256gcm_encrypt_to_slice, AesNonce, AES_NONCE_SIZE, AES_OUT_AUTH_TAG_SIZE};
use libsodium_sys::rust_wrappings::init::sodium_init;
use libsodium_sys::rust_wrappings::x25519::{shared_secret_to_aes_key, PubKey, SecKey, SharedSecret, ECIES_PK_SIZE, ECIES_SK_SIZE};

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
fn get_wrapped_session_key(sec_key: &SecKey) -> (WrappedSessionKey, SessionKeyNonce) {
    let halo = [40u8, 167, 39, 179, 72, 65, 122, 230, 190, 236, 125, 99, 81, 178, 50, 71, 35, 205, 141, 170, 74, 54, 227, 7, 92, 208, 212, 206, 126, 216, 55, 37];

    let params = Params::new(
        64*1024,           // 메모리 요구량 (KB 단위)
        1,                  // 반복 횟수
        6,                 // 병렬 처리 수준
        Some(SESSION_KEY_SIZE),  // 출력 길이
    ).unwrap();
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        params
    );

    let mut rust_owned_sec_key = [0u8; ECIES_SK_SIZE];
    hint::black_box(rust_owned_sec_key.as_mut_ptr());
    sec_key.copy_to(rust_owned_sec_key.as_mut_ptr());
    let mut rust_owned_sess_key = [0u8; SESSION_KEY_SIZE];
    hint::black_box(rust_owned_sec_key.as_mut_ptr());
    argon2
        .hash_password_into(rust_owned_sec_key.as_slice(), &halo, rust_owned_sess_key.as_mut_slice())
        .unwrap();
    rust_owned_sec_key.zeroize();
    let session_key = SessionKey::from_raw(rust_owned_sess_key.as_ptr());
    rust_owned_sess_key.zeroize();

    wrap_session_key(session_key)
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
    let mut kdf_out = [0u8; ECIES_SK_SIZE];
    hint::black_box(kdf_out.as_mut_ptr());
    argon2.hash_password_into(
        master_pw.as_bytes(), salt,
        kdf_out.as_mut()
    ).unwrap();
    let sec_key = SecKey::from_raw(kdf_out.as_ptr());
    kdf_out.zeroize();
    sec_key
}


pub fn general_login(master_pw: &mut String, salt: &Salt)
                     -> (SecKey, PubKey, WrappedSessionKey, SessionKeyNonce) {
    let sec_key = master_pw_kdf(master_pw, salt);
    master_pw.zeroize();
    let pub_key = PubKey::from_sec_key(&sec_key);
    let (wrapped_session_key, session_key_nonce) = get_wrapped_session_key(&sec_key);

    (sec_key, pub_key, wrapped_session_key, session_key_nonce)
}
pub fn first_login(mut master_pw: String)
    -> (PubKey, Salt, WrappedSessionKey, SessionKeyNonce) {
    let mut salt = Salt::default();
    OsRng.fill_bytes(salt.as_mut_slice());
    let sec_key = master_pw_kdf(&master_pw, &salt);

    master_pw.zeroize();

    let pub_key = PubKey::from_sec_key(&sec_key);
    let (wrapped_session_key, session_key_nonce) = get_wrapped_session_key(&sec_key);
    drop(sec_key);

    (pub_key, salt, wrapped_session_key, session_key_nonce)
}
pub fn change_master_pw(db: &mut DB, mut new_master_pw: String, wrapped_session_key: &mut WrappedSessionKey, session_key_nonce: &mut SessionKeyNonce)
                        -> Result<(PubKey, Salt), DBIOError> {
    let mut salt = Salt::default();
    OsRng.fill_bytes(salt.as_mut_slice());
    let sec_key = master_pw_kdf(&new_master_pw, &salt);

    new_master_pw.zeroize();

    let mut pub_key = PubKey::from_sec_key(&sec_key);
    let (new_wrapped_user_key, new_user_key_nonce) = get_wrapped_session_key(&sec_key);
    drop(sec_key);

    let mut users_archive = vec![];
    for site in &mut *db {
        for user in site.1 {

            users_archive.push((site.0.clone(), user.0.clone()));
        }
    }

    for user in users_archive.into_iter() {

        let user_pw = get_user_pw(&db, &user.0, &user.1, &wrapped_session_key, &session_key_nonce).unwrap();

        change_user_pw(&mut *db, &user.0, &user.1, user_pw, &new_wrapped_user_key, &new_user_key_nonce)?;
    }

    wrapped_session_key.zeroize();
    *wrapped_session_key = new_wrapped_user_key;
    session_key_nonce.zeroize();
    *session_key_nonce = new_user_key_nonce;
    Ok( (pub_key, salt) )
}


thread_local! {
    static __SODIUM_INIT: () = sodium_init().unwrap();
}

const AES_NONCE_BEGIN: usize = ECIES_PK_SIZE;
const AES_NONCE_END: usize = AES_NONCE_BEGIN + AES_NONCE_SIZE;
const CIPHERTEXT_BEGIN: usize = AES_NONCE_END.next_power_of_two();

pub type EncryptedDB = Vec<u8>;

pub fn encrypt_db(db: &DB, pk: &PubKey,) -> EncryptedDB {
    let mut serialized =
        rkyv::to_bytes::<Error>(db).unwrap();

    let peer_sk = SecKey::gen_rand();
    let shared = SharedSecret::from_sk_pk(&peer_sk, &pk);
    let once_aes_key = shared_secret_to_aes_key(&shared);
    drop(shared);
    let peer_pk = PubKey::from_sec_key(&peer_sk);
    drop(peer_sk);
    let nonce = AesNonce::gen_rand();

    let len = CIPHERTEXT_BEGIN + serialized.len() + AES_OUT_AUTH_TAG_SIZE;
    let mut result = Vec::with_capacity(len);
    unsafe { result.set_len(len) }
    aes256gcm_encrypt_to_slice(&once_aes_key, &nonce, &serialized, &mut result[CIPHERTEXT_BEGIN..]);
    serialized.zeroize();
    peer_pk.copy_to(addr_of_mut!(result[0]));
    nonce.copy_to(addr_of_mut!(result[AES_NONCE_BEGIN]));

    result
}

pub fn decrypt_db(bytes: &Vec<u8>, sk: SecKey) -> Result<DB, MasterPWError> {
    let peer_pk = PubKey::from_raw(addr_of!(bytes[0]));
    let nonce: AesNonce = AesNonce::from_raw(addr_of!(bytes[AES_NONCE_BEGIN]));
    let ciphertext = &bytes[CIPHERTEXT_BEGIN..];

    let shared = SharedSecret::from_sk_pk(&sk, &peer_pk);
    drop(sk);
    let once_aes_key = shared_secret_to_aes_key(&shared);
    drop(shared);

    let mut plaintext =
        aes256gcm_decrypt(&once_aes_key, &nonce, &ciphertext)
            .map_err(|_| MasterPWError::IncorrectPW)?;
    drop(once_aes_key);
    let mut rust_owned_buf = Vec::with_capacity(plaintext.len());
    unsafe {rust_owned_buf.set_len(plaintext.len());}
    plaintext.copy_to(rust_owned_buf.as_mut_ptr());
    plaintext.zeroize();

    let db =
        rkyv::from_bytes::<DB, Error>(&rust_owned_buf).unwrap();
    rust_owned_buf.zeroize();

    Ok( db )
}


#[macro_export]
macro_rules! manual_zeroize {
    ($($var:expr),+ $(,)?) => {
        $(
            static_type_zeroize(&mut $var);
        )+
    };
}

pub fn static_type_zeroize<T>(data: &mut T) {
    let size = std::mem::size_of::<T>();
    let ptr = data as *mut T as *mut u8;
    unsafe {
        for i in 0..size {
            ptr::write_volatile(ptr.add(i), 0);
        }
    }
}