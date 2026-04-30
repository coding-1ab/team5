use crate::data_base::{DB, DBIOError, change_user_pw, get_user_pw};
use crate::header::Salt;
use crate::user_secrets::{
    SESSION_KEY_SIZE, SessionKey, SessionKeyNonce, WrappedSessionKey, wrap_session_key,
};
use argon2::password_hash::rand_core;
use argon2::{Argon2, Params};
use libsodium_sys::rust_wrappings::aes256gcm::{AES_NONCE_SIZE, AesNonce, get_aes256gcm_ciphertext_len, get_aes256gcm_plaintext_len, aes256gcm_decrypt_write_to_ptr, aes256gcm_encrypt_write_to_ptr};
use libsodium_sys::rust_wrappings::init::sodium_init;
use libsodium_sys::rust_wrappings::x25519::*;
use rand_core::OsRng;
use rand_core::RngCore;
use rkyv::rancor::Error;
use std::error::Error as StdError;
use std::fmt::{Debug, Display, Formatter};
use std::ptr::{addr_of, addr_of_mut};
use std::{hint, ptr};
use std::alloc::GlobalAlloc;
use std::arch::x86_64::_mm_clflush;
use std::sync::atomic::{fence, Ordering};
use rkyv::util::AlignedVec;
use secrecy::{ExposeSecret, ExposeSecretMut, SecretBox};
use zeroize::{Zeroize};
use libsodium_sys::rust_wrappings::sodium_box::SodiumBox;

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum MasterPWError {
    // 생성
    Empty,
    TooShort,
    ContainsWhitespace,

    // 로그인
    IncorrectPW,

    // 프로세스 유효성
    InvalidSession,
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
#[inline(always)]
pub fn master_pw_validation(raw_pw: &String) -> Result<(), MasterPWError> {
    let trimmed = raw_pw.trim();

    if trimmed.is_empty() {
        return Err(MasterPWError::Empty);
    }
    if trimmed.len() < 8 {
        return Err(MasterPWError::TooShort);
    }
    if trimmed.chars().any(|c| c.is_whitespace()) {}

    Ok(())
}

#[inline(always)]
fn master_pw_kdf(master_pw: &str, salt: &Salt) -> SecKey {
    let params = Params::new(
        128 * 1024, // 메모리 요구량 (KB 단위)
        1,          // 반복 횟수
        12,         // 병렬 처리 수준
        Some(32),   // 출력 길이
    )
    .unwrap();
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut kdf_out = [0u8; ECIES_SK_SIZE];
    hint::black_box(kdf_out.as_mut_ptr());
    argon2
        .hash_password_into(master_pw.as_bytes(), salt, kdf_out.as_mut())
        .unwrap();
    let sec_key = SecKey::from_raw(kdf_out.as_ptr());
    manual_zeroize(&mut kdf_out);
    sec_key
}

#[inline]
fn get_wrapped_session_key(sec_key: &SecKey) -> (WrappedSessionKey, SessionKeyNonce) {
    let halo = [
        40u8, 167, 39, 179, 72, 65, 122, 230, 190, 236, 125, 99, 81, 178, 50, 71, 35, 205, 141,
        170, 74, 54, 227, 7, 92, 208, 212, 206, 126, 216, 55, 37,
    ];

    let params = Params::new(
        64 * 1024,              // 메모리 요구량 (KB 단위)
        1,                      // 반복 횟수
        6,                      // 병렬 처리 수준
        Some(SESSION_KEY_SIZE), // 출력 길이
    )
    .unwrap();
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

    let mut rust_owned_sec_key = [0u8; ECIES_SK_SIZE];
    hint::black_box(rust_owned_sec_key.as_mut_ptr());
    sec_key.copy_to(rust_owned_sec_key.as_mut_ptr());
    let mut rust_owned_sess_key = [0u8; SESSION_KEY_SIZE];
    hint::black_box(rust_owned_sec_key.as_mut_ptr());
    argon2
        .hash_password_into(
            rust_owned_sec_key.as_slice(),
            &halo,
            rust_owned_sess_key.as_mut_slice(),
        )
        .unwrap();
    manual_zeroize(&mut rust_owned_sec_key);
    let session_key = SessionKey::from_raw(rust_owned_sess_key.as_ptr());
    manual_zeroize(&mut rust_owned_sess_key);

    wrap_session_key(session_key)
}

pub fn general_login(
    master_pw: &mut String,
    salt: &Salt,
) -> (SecKey, PubKey, WrappedSessionKey, SessionKeyNonce) {
    let sec_key = master_pw_kdf(master_pw, salt);
    manual_zeroize(master_pw);
    let pub_key = PubKey::from_sec_key(&sec_key);
    let (wrapped_session_key, session_key_nonce) = get_wrapped_session_key(&sec_key);

    (sec_key, pub_key, wrapped_session_key, session_key_nonce)
}
pub fn first_login(master_pw: &mut String) -> (PubKey, Salt, WrappedSessionKey, SessionKeyNonce) {
    let mut salt = Salt::default();
    OsRng.fill_bytes(salt.as_mut_slice());
    let sec_key = master_pw_kdf(master_pw.trim(), &salt);

    manual_zeroize(master_pw);

    let pub_key = PubKey::from_sec_key(&sec_key);
    let (wrapped_session_key, session_key_nonce) = get_wrapped_session_key(&sec_key);
    drop(sec_key);

    (pub_key, salt, wrapped_session_key, session_key_nonce)
}
pub fn change_master_pw(
    db: &mut DB,
    new_master_pw: &mut String,
    wrapped_session_key: &mut WrappedSessionKey,
    session_key_nonce: &mut SessionKeyNonce,
) -> Result<(PubKey, Salt), DBIOError> {
    let mut salt = Salt::default();
    OsRng.fill_bytes(salt.as_mut_slice());
    let sec_key = master_pw_kdf(new_master_pw.trim(), &salt);

    manual_zeroize(new_master_pw);

    let pub_key = PubKey::from_sec_key(&sec_key);
    let (new_wrapped_user_key, new_user_key_nonce) = get_wrapped_session_key(&sec_key);
    drop(sec_key);

    let mut users_archive = vec![];
    for site in &mut *db {
        for user in site.1 {
            users_archive.push((site.0.clone(), user.0.clone()));
        }
    }

    for user in users_archive.into_iter() {
        let user_pw = get_user_pw(
            &db,
            &user.0,
            &user.1,
            &wrapped_session_key,
            &session_key_nonce,
        )?;

        change_user_pw(
            &mut *db,
            &user.0,
            &user.1,
            user_pw,
            &new_wrapped_user_key,
            &new_user_key_nonce,
        )?;
    }

    *wrapped_session_key = new_wrapped_user_key;
    *session_key_nonce = new_user_key_nonce;
    Ok( (pub_key, salt) )
}

thread_local! {
    static __SODIUM_INIT: () = sodium_init().unwrap();
}

const AES_PK_BEGIN: usize = 0;
const AES_NONCE_BEGIN: usize = AES_PK_BEGIN + ECIES_PK_SIZE;
const AES_NONCE_END: usize = AES_NONCE_BEGIN + AES_NONCE_SIZE;
const CIPHERTEXT_BEGIN: usize = AES_NONCE_END.next_power_of_two();

pub type EncryptedDB = Vec<u8>;

pub fn encrypt_db(db: &DB, pk: &PubKey) -> EncryptedDB {
    let peer_sk = SecKey::gen_rand();
    let shared = SharedSecret::from_sk_pk(&peer_sk, &pk);
    let once_aes_key = shared_secret_to_aes_key(&shared);
    drop(shared);
    let peer_pk = PubKey::from_sec_key(&peer_sk);
    drop(peer_sk);
    let nonce = AesNonce::gen_rand();

    let mut serialized = rkyv::to_bytes::<Error>(db).unwrap();
    let len = CIPHERTEXT_BEGIN + get_aes256gcm_ciphertext_len(serialized.len());

    let mut result = vec![Default::default(); len];
    aes256gcm_encrypt_write_to_ptr(
        &once_aes_key,
        &nonce,
        &serialized,
        addr_of_mut!(result[CIPHERTEXT_BEGIN]),
    );
    manual_zeroize(&mut serialized);

    peer_pk.copy_to(addr_of_mut!(result[AES_PK_BEGIN]));
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

    let plaintext_len = get_aes256gcm_plaintext_len(ciphertext.len());
    let mut plaintext = vec![Default::default(); plaintext_len];
    aes256gcm_decrypt_write_to_ptr(&once_aes_key, &nonce, &ciphertext, plaintext.as_mut_ptr())
        .map_err(|_| MasterPWError::IncorrectPW)?;
    drop(once_aes_key);

    let db = rkyv::from_bytes::<DB, Error>(&plaintext).unwrap();
    manual_zeroize(&mut plaintext);
    Ok(db)
}

// #[macro_export]
// macro_rules! manual_zeroize {
//     ($($var:expr),+ $(,)?) => {
//         $(
//             static_type_zeroize(&mut $var);
//         )+
//     };
// }

#[inline(always)]
fn make_safety_array<const N: usize>() -> [u8; N] {
    let mut arr = [0u8; N];
    hint::black_box(arr.as_mut_ptr());
    //todo
    arr
}

trait ArrLike {
    fn as_mut_ptr(&mut self) -> *mut u8;
    fn len(&self) -> usize;
    fn zeroize(&mut self);
}
impl<const N: usize> ArrLike for [u8; N] {
    fn as_mut_ptr(&mut self) -> *mut u8 { addr_of_mut!(self[0]) }
    fn len(&self) -> usize { N }
    fn zeroize(&mut self) { Zeroize::zeroize(self); }
}
impl ArrLike for Vec<u8> {
    fn as_mut_ptr(&mut self) -> *mut u8 { self.as_mut_ptr() }
    fn len(&self) -> usize { self.len() }
    fn zeroize(&mut self) { Zeroize::zeroize(self) }
}
impl<const M: usize> ArrLike for AlignedVec<M> {
    fn as_mut_ptr(&mut self) -> *mut u8 { self.as_mut_ptr() }
    fn len(&self) -> usize { self.len() }
    fn zeroize(&mut self) { Zeroize::zeroize(self.as_mut_slice()); }
}
impl ArrLike for String {
    fn as_mut_ptr(&mut self) -> *mut u8 { self.as_mut().as_mut_ptr() }
    fn len(&self) -> usize { self.len() }
    fn zeroize(&mut self) { Zeroize::zeroize(self) }
}
impl ArrLike for SecretBox<[u8]> {
    fn as_mut_ptr(&mut self) -> *mut u8 { self.expose_secret_mut().as_mut_ptr() }
    fn len(&self) -> usize { self.expose_secret().len() }
    fn zeroize(&mut self) { Zeroize::zeroize(self) }
}
pub fn manual_zeroize<T: ArrLike>(data: &mut T) {
    flush_cache_line(data.as_mut_ptr(), data.len());
    fence(Ordering::SeqCst);
    data.zeroize();
}

pub fn flush_cache_line<T>(ptr: *mut T, len: usize) {
    let ptr_cast = ptr as *mut u8;
    let len_bytes = len * size_of::<T>() / 8;

    let mut p_cache_line = ptr_cast;
    loop {
        unsafe {
            _mm_clflush(p_cache_line);

            if p_cache_line < ptr_cast.add(len_bytes) {
                p_cache_line = p_cache_line.add(64);
            } else {
                break;
            }
        }
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
