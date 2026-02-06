use crate::manual_zeroize;
use crate::header::{EncryptedDB as OtherEncryptedDB, Salt};
use crate::user_secrets::{decrypt_user_pw, get_system_identity, wrap_user_key, UserKey, WrappedUserKey};
use aes_gcm::Aes256Gcm;
use argon2::password_hash::rand_core;
use argon2::{Argon2, Params, ParamsBuilder};
use ecies::PublicKey;
use ecies::SecretKey;
use rand_core::OsRng;
// use rand::RngCore::SeedableRng;
// use rand::rngs::OsRng;
// use rand::RngCore;
use rand_core::RngCore;
use sha2::digest::generic_array::GenericArray;
use sha2::Digest;
use sha2::Sha256;
use std::ptr;
use rand::prelude::{IteratorRandom, ThreadRng};
use rkyv::rancor::Error;
use sha2::digest::FixedOutputReset;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};
use zeroize::__internal::AssertZeroize;
use crate::data_base::{change_user_pw, get_password, DB};

use std::fmt::{Display, Formatter};
use std::str::FromStr;
use crate::data_base::{UserPW, UserPWError};

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum MasterPWError {
    // 생성
    Empty,
    TooShort,
    ContainsWitespace,

    // 로그인
    IncorrectPW,

    // 프로세스 유효성
    InvalidSession
}
pub fn master_pw_validation(mut raw_pw: &String) -> Result<(), MasterPWError> {

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
            MasterPWError::ContainsWitespace => {
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


#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PubKey(Box<[u8; 65]>);
impl PubKey {
    pub fn from_sec_key(sk: &SecKey) -> Self {
        let mut sk_obj = SecretKey::parse(sk.as_array()).unwrap();
        let mut pk_obj = PublicKey::from_secret_key(&sk_obj);
        manual_zeroize!(sk_obj);
        let pk = Box::new(pk_obj.serialize());
        manual_zeroize!(pk_obj);
        Self ( pk )
    }
    pub fn as_array(&self) -> &[u8; 65] {
        &self.0
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecKey(Box<[u8; 32]>);
impl SecKey {
    pub fn from_array(mut sk: [u8; 32]) -> SecKey {
        let boxed = Box::new(sk);
        sk.zeroize();
        Self ( boxed )
    }
    pub fn as_array(&self) -> &[u8; 32] {
        &self.0
    }
}
impl From<SecretKey> for SecKey {
    fn from(mut sk: SecretKey) -> SecKey {
        let boxed = Box::new(sk.serialize());
        manual_zeroize!(sk);
        Self ( boxed )
    }
}

#[inline]
fn master_pw_kdf(master_pw: &String, mut salt: Salt) -> SecKey {
    salt[5]=5; salt[10]=10; salt[15]=15; salt[20]=20; salt[25]=25; salt[30]=30;
    for (t, s) in salt.iter_mut().zip(master_pw.as_bytes().iter()) {
        *t ^= *s;
    }
    let mut params = Params::new(
        65536, // 64MB 지정 (KB 단위)
        8,      // 반복 횟수
        3,     // 병렬 처리 수준
        Some(32),     // 출력 길이
    ).unwrap();
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        params
    );
    let mut kdf_out = [0u8; 32];
    argon2.hash_password_into(
        master_pw.as_bytes(), salt.as_slice(),
        kdf_out.as_mut()
    ).unwrap();
    let sec_key = SecKey::from_array(kdf_out);
    kdf_out.zeroize();
    sec_key
}


// secp256k1 곡선의 유효 범위 (N)
const SECP256K1_ORDER: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
    0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
];
fn is_valid_sec_key(key: &[u8; 32]) -> bool {
    let is_zero = key.iter().all(|&b| b == 0);
    if is_zero { return false; }
    for i in 0..32 {
        if key[i] < SECP256K1_ORDER[i] { return true; }
        if key[i] > SECP256K1_ORDER[i] { return false; }
    }
    false
}

pub fn general_login(mut master_pw: String, mut salt: Salt)
                     -> Result<(SecKey, PubKey, WrappedUserKey), MasterPWError> {
    let mut sec_key = master_pw_kdf(&master_pw, salt);
    if !is_valid_sec_key(sec_key.as_array()) {
        sec_key.zeroize();
        return Err(MasterPWError::IncorrectPW);
    }
    let pub_key = PubKey::from_sec_key(&sec_key);
    let wrapped_user_key = get_wrapped_user_key(&master_pw, &sec_key);
    master_pw.zeroize();
    sec_key.zeroize();
    Ok( (sec_key, pub_key, wrapped_user_key) )
}
pub fn first_login(mut master_pw: String) -> (PubKey, Salt, WrappedUserKey) {
    let mut salt = Salt::default();
    let mut sec_key;
    loop {
        OsRng.fill_bytes(salt.as_mut_slice());
        sec_key = master_pw_kdf(&master_pw, salt);
        if is_valid_sec_key(sec_key.as_array()) {
            break;
        }
    }
    let pub_key = PubKey::from_sec_key(&sec_key);
    let wrapped_user_key = get_wrapped_user_key(&master_pw, &sec_key);
    master_pw.zeroize();
    sec_key.zeroize();
    (pub_key, salt, wrapped_user_key)
}
pub fn change_master_pw(db: &mut DB, mut new_master_pw: String, wrapped_user_key: WrappedUserKey)
                        -> Result<(PubKey, Salt, WrappedUserKey), MasterPWError> {
    let mut salt = Salt::default();
    let mut sec_key;
    loop {
        OsRng.fill_bytes(salt.as_mut_slice());
        sec_key = master_pw_kdf(&new_master_pw, salt);
        if is_valid_sec_key(sec_key.as_array()) {
            break;
        }
    }
    let pub_key = PubKey::from_sec_key(&sec_key);
    let new_wrapped_user_key = get_wrapped_user_key(&new_master_pw, &sec_key);
    new_master_pw.zeroize();
    sec_key.zeroize();

    let mut users_archive = vec![];
    for site in &mut *db {
        for user in site.1 {
            users_archive.push((site.0.clone(), user.0.clone()));
        }
    }
    for user in users_archive.into_iter() {
        let user_pw = get_password(&db, &user.0, &user.1, &wrapped_user_key)
            .map_err(|err| MasterPWError::InvalidSession)?;
        change_user_pw(&mut *db, user.0, user.1, user_pw, &new_wrapped_user_key)
            .map_err(|err| MasterPWError::InvalidSession)?;
    }
    // users_archive.zeroize();
    Ok( (pub_key, salt, new_wrapped_user_key) )
}
fn get_wrapped_user_key(master_pw: &String, sec_key: &SecKey) -> WrappedUserKey {
    let mut hasher1 = Sha256::new();
    hasher1.update(master_pw.as_bytes());
    let mut hasher2 = hasher1.clone();
    let mut tmp = [0u8;32];
    FixedOutputReset::finalize_into_reset(&mut hasher1, GenericArray::from_mut_slice(tmp.as_mut_slice()));
    hasher2.update(sec_key.as_array());
    hasher2.update(&tmp);
    hasher2.update(&tmp);
    let mut user_key = UserKey::default();
    FixedOutputReset::finalize_into_reset(&mut hasher2, GenericArray::from_mut_slice(user_key.as_mut_slice()));
    tmp.zeroize();
    let wrapped_user_key = wrap_user_key(user_key).unwrap();
    wrapped_user_key
}

// pub fn get_master_pw_hash(master_pw: &String) -> Box<[u8; 32]> {
//     let mut hasher = Sha256::new();
//     let mut system_info = get_system_identity();
//     hasher.update(*system_info);
//     system_info.zeroize();
//     hasher.update(master_pw.as_bytes());
//     let mut hash = Box::new([0u8; 32]);
//     FixedOutputReset::finalize_into_reset(&mut hasher, GenericArray::from_mut_slice(&mut *hash));
//     hash
// }

pub type EncryptedDB = Vec<u8>;

pub fn encrypt_db(db: &DB, pk: &PubKey,)
                  -> EncryptedDB {
    let mut serialized = rkyv::to_bytes::<Error>(db).unwrap();
    let encrypted = ecies::encrypt(pk.as_array(), &serialized).unwrap();
    serialized.zeroize();

    encrypted
}

pub fn decrypt_db(bytes: &[u8], mut sk: SecKey,
) -> Result<DB, MasterPWError> {
    let mut decrypted = ecies::decrypt(sk.as_array(), &bytes)
        .map_err(|_| MasterPWError::IncorrectPW)?;
    sk.zeroize();
    let db = rkyv::from_bytes::<DB, Error>(&decrypted).unwrap();
    decrypted.zeroize();

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
