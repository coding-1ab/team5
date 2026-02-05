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

pub type MasterKey = Box<[u8; 32]>;

// secp256k1 곡선의 유효 범위 (N)
const SECP256K1_ORDER: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
    0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
];
fn is_valid_ecies_key(key: &[u8; 32]) -> bool {
    let is_zero = key.iter().all(|&b| b == 0);
    if is_zero { return false; }
    for i in 0..32 {
        if key[i] < SECP256K1_ORDER[i] { return true; }
        if key[i] > SECP256K1_ORDER[i] { return false; }
    }
    false
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

#[inline]
fn master_pw_kdf(master_pw: &String, mut salt: Salt) -> MasterKey {
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
    let mut kdf_out = MasterKey::default();
    argon2.hash_password_into(master_pw.as_bytes(), salt.as_slice(), kdf_out.as_mut())
        .unwrap();
    salt.zeroize();
    kdf_out
}

pub struct EciesKeyPair {pub pk: Box<PublicKey>, pub sk: Box<SecretKey>}
impl EciesKeyPair {
    pub fn new(mut pk: PublicKey, mut sk: SecretKey) -> EciesKeyPair {
        let result = EciesKeyPair { pk: Box::new(pk), sk: Box::new(sk) };
        manual_zeroize!(pk, sk);
        result
    }
}
impl Zeroize for EciesKeyPair {
    fn zeroize(&mut self) {
        manual_zeroize!(*(self.pk));
        manual_zeroize!(*(self.sk));
    }
}
// impl Drop for EciesKeyPair {
//     fn drop(&mut self) {
//         self.zeroize();
//     }
// }
impl ZeroizeOnDrop for EciesKeyPair {}
pub fn get_ecies_keypair(kdf_key: &MasterKey) -> Result<EciesKeyPair, MasterPWError> {
    let sk = SecretKey::parse(&kdf_key)
        .map_err(|_| MasterPWError::IncorrectPW)?;
    let pk = PublicKey::from_secret_key(&sk);
    Ok(  EciesKeyPair::new(pk, sk) )
}

pub fn check_master_pw_and_login(mut master_pw: String, mut salt: Salt)
                                 -> Result<(EciesKeyPair, WrappedUserKey), MasterPWError> {
    let mut master_key = master_pw_kdf(&master_pw, salt);
    salt.zeroize();
    let ecies_key_pair = get_ecies_keypair(&master_key)?;
    let wrapped_user_key = get_wrapped_user_key(&master_pw, &master_key);
    master_pw.zeroize();
    master_key.zeroize();
    Ok( (ecies_key_pair, wrapped_user_key) )
}
pub fn set_master_pw_and_1st_login(mut master_pw: String) -> (EciesKeyPair, Salt, WrappedUserKey) {
    let mut salt = Salt::default();
    let mut master_key = MasterKey::default();
    loop {
        OsRng.fill_bytes(salt.as_mut_slice());
        master_key = master_pw_kdf(&master_pw, salt);
        if is_valid_ecies_key(&master_key) {
            break;
        }
    }
    let ecies_key_pair = get_ecies_keypair(&master_key).ok().unwrap();
    let wrapped_user_key = get_wrapped_user_key(&master_pw, &master_key);
    master_pw.zeroize();
    master_key.zeroize();
    (ecies_key_pair, salt, wrapped_user_key)
}
pub fn change_master_pw(db: &mut DB, mut new_master_pw: String, wrapped_user_key: WrappedUserKey)
                        -> Result<(Box<PublicKey>, Salt, WrappedUserKey), MasterPWError> {
    let mut salt = Salt::default();
    let mut master_key = MasterKey::default();
    loop {
        OsRng.fill_bytes(salt.as_mut_slice());
        master_key = master_pw_kdf(&new_master_pw, salt);
        if is_valid_ecies_key(&master_key) {
            break;
        }
    }
    let ecies_pub_key = get_ecies_keypair(&master_key).ok().unwrap().pk;
    let new_wrapped_user_key = get_wrapped_user_key(&new_master_pw, &master_key);
    new_master_pw.zeroize();
    master_key.zeroize();

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
    Ok( (ecies_pub_key, salt, new_wrapped_user_key) )
}
pub fn get_wrapped_user_key(master_pw: &String, mster_key: &MasterKey) -> WrappedUserKey {
    let mut hasher1 = Sha256::new();
    hasher1.update(master_pw.as_bytes());
    let mut hasher2 = hasher1.clone();
    let mut tmp = [0u8;32];
    FixedOutputReset::finalize_into_reset(&mut hasher1, GenericArray::from_mut_slice(tmp.as_mut_slice()));
    hasher2.update(mster_key.as_slice());
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

pub fn encrypt_db(db: &DB, pk: &Box<PublicKey>,)
                  -> Result<EncryptedDB, MasterPWError> {
    let mut serialized = rkyv::to_bytes::<Error>(db).unwrap();
    let encrypted = ecies::encrypt(&pk.serialize(), &serialized).unwrap();
    serialized.zeroize();

    Ok( encrypted )
}

pub fn decrypt_db(bytes: &[u8], mut sk: Box<SecretKey>,
) -> Result<DB, MasterPWError> {
    let mut decrypted = ecies::decrypt(&sk.serialize(), &bytes)
        .map_err(|_| MasterPWError::IncorrectPW)?;
    manual_zeroize!(*sk);
    let db = rkyv::from_bytes::<DB, Error>(&decrypted).unwrap();
    decrypted.zeroize();

    Ok( db )
}

