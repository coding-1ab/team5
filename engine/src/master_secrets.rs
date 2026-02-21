use crate::manual_zeroize;
use crate::header::{Salt};
use crate::user_secrets::{wrap_user_key, UserKey, WrappedUserKey};
use argon2::password_hash::rand_core;
use argon2::{Argon2, Params};
use ecies::PublicKey;
use ecies::SecretKey;
use rand_core::OsRng;
use rand_core::RngCore;
use std::ptr;
use rkyv::rancor::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};
use crate::data_base::{change_user_pw, get_user_pw, DB};
use std::fmt::{Display, Formatter};
use std::error::Error as StdError;
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


pub struct PubKey (
    SecretBox<[u8; 65]>,
);
impl PubKey {
    pub fn from_sec_key(sk: &SecKey) -> Self {
        let mut sk_obj = SecretKey::parse(sk.as_array()).unwrap();
        let mut pk_obj = PublicKey::from_secret_key(&sk_obj);
        manual_zeroize!(sk_obj);
        let boxed_pk = Box::new(pk_obj.serialize());
        manual_zeroize!(pk_obj);
        Self (SecretBox::new(boxed_pk))
    }
    pub fn as_array(&self) -> &[u8; 65] {
        self.0.expose_secret()
    }
}
impl Zeroize for PubKey {
    fn zeroize(&mut self) {
        self.0.expose_secret_mut().zeroize();
    }
}
impl ZeroizeOnDrop for PubKey {}

pub struct SecKey (
    SecretBox<[u8; 32]>,
);
impl SecKey {
    pub fn from_array(mut sk: [u8; 32]) -> SecKey {
        let boxed = Box::new(sk);
        sk.zeroize();

        Self (SecretBox::new(boxed))
    }
    pub fn as_array(&self) -> &[u8; 32] {
        self.0.expose_secret()
    }
}
impl Zeroize for SecKey {
    fn zeroize(&mut self) {
        self.0.expose_secret_mut().zeroize();
    }
}
impl ZeroizeOnDrop for SecKey {}


#[inline]
fn get_wrapped_user_key(sec_key: &SecKey) -> WrappedUserKey {
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
        .hash_password_into(&sec_key.as_array().as_slice(), &halo, user_key.as_mut_bytes())
        .unwrap();

    let wrapped_user_key = wrap_user_key(user_key);
    wrapped_user_key
}

fn master_pw_kdf(master_pw: &String, salt: &Salt) -> SecKey {
    let params = Params::new(
        128*1024, // 메모리 요구량 (KB 단위)
        2,         // 반복 횟수
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

pub fn general_login(master_pw: &mut String, salt: &Salt)
                     -> Result<(SecKey, PubKey, WrappedUserKey), MasterPWError> {
    let mut sec_key = master_pw_kdf(master_pw, salt);
    master_pw.zeroize();
    if !is_valid_sec_key(sec_key.as_array()) {
        sec_key.zeroize();
        return Err(MasterPWError::IncorrectPW);
    }

    let pub_key = PubKey::from_sec_key(&sec_key);
    let wrapped_user_key = get_wrapped_user_key(&sec_key);
    Ok( (sec_key, pub_key, wrapped_user_key) )
}
pub fn first_login(mut master_pw: String) -> (PubKey, Salt, WrappedUserKey) {
    let mut salt = Salt::default();
    let mut sec_key;
    loop {
        OsRng.fill_bytes(salt.as_mut_slice());
        sec_key = master_pw_kdf(&master_pw, &salt);
        if is_valid_sec_key(sec_key.as_array()) {
            break;
        }
    }
    master_pw.zeroize();

    let pub_key = PubKey::from_sec_key(&sec_key);
    let wrapped_user_key = get_wrapped_user_key(&sec_key);
    sec_key.zeroize();

    (pub_key, salt, wrapped_user_key)
}
pub fn change_master_pw(db: &mut DB, mut new_master_pw: String, wrapped_user_key: &mut WrappedUserKey)
                        -> Result<(PubKey, Salt), MasterPWError> {
    let mut salt = Salt::default();
    let mut sec_key;
    loop {
        OsRng.fill_bytes(salt.as_mut_slice());
        sec_key = master_pw_kdf(&new_master_pw, &salt);
        if is_valid_sec_key(sec_key.as_array()) {
            break;
        }
    }
    new_master_pw.zeroize();

    let mut pub_key = PubKey::from_sec_key(&sec_key);
    let mut new_wrapped_user_key = get_wrapped_user_key(&sec_key);
    sec_key.zeroize();

    let mut users_archive = vec![];
    for site in &mut *db {
        for user in site.1 {

            users_archive.push((site.0.clone(), user.0.clone()));
        }
    }

    for user in users_archive.into_iter() {

        let user_pw = get_user_pw(&db, &user.0, &user.1, &wrapped_user_key).unwrap();

        if let Err(_) = change_user_pw(&mut *db, &user.0, &user.1, user_pw, &new_wrapped_user_key) {
            pub_key.zeroize();
            new_wrapped_user_key.zeroize();
            return Err(MasterPWError::InvalidSession);
        }
    }

    wrapped_user_key.zeroize();
    *wrapped_user_key = new_wrapped_user_key;
    Ok( (pub_key, salt) )
}


pub type EncryptedDB = Vec<u8>;

pub fn encrypt_db(db: &DB, pk: &PubKey,) -> EncryptedDB {
    let mut serialized = rkyv::to_bytes::<Error>(db).unwrap();
    let encrypted = ecies::encrypt(pk.as_array(), &serialized).unwrap();
    serialized.zeroize();

    encrypted
}

pub fn decrypt_db(bytes: &[u8], mut sk: SecKey, ) -> Result<DB, MasterPWError> {
    let mut decrypted = match ecies::decrypt(sk.as_array(), &bytes) {
        Ok(v) => {v}
        Err(_) => {
            sk.zeroize();
            return Err(MasterPWError::IncorrectPW)
        }
    };
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
