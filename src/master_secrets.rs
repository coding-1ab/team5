use crate::header::{EncryptedDB as OtherEncryptedDB, Salt};
use crate::user_secrets::{wrap_user_key, UserKey, WrappedUserKey};
use aes_gcm::Aes256Gcm;
use argon2::password_hash::rand_core;
use argon2::{Argon2, ParamsBuilder};
use ecies::PublicKey;
use ecies::SecretKey;
use master_pw::*;
use rand_core::OsRng;
// use rand::RngCore::SeedableRng;
// use rand::rngs::OsRng;
// use rand::RngCore;
use rand_core::RngCore;
use sha2::digest::generic_array::GenericArray;
use sha2::Digest;
use sha2::Sha256;
use std::ptr;
use rkyv::rancor::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};
use crate::data_base::DB;

pub mod master_pw {
    use zeroize::{Zeroize, ZeroizeOnDrop};

    #[derive(Debug, Clone, Eq, PartialEq)]
    pub enum MasterPWError {
        // 생성
        Empty,
        TooShort,
        TooLong,
        NonAscii,

        // 로그인
        IncorrectPW
    }

    // const MAX_MASTER_PW_LEN: usize = 32;

    #[derive(Zeroize, ZeroizeOnDrop)]
    pub struct MasterPW (String);

    impl MasterPW {
        pub fn new(raw_pw: &str) -> Result<MasterPW, MasterPWError> {
            if raw_pw.is_empty() {
                return Err(MasterPWError::Empty);
            }
            if raw_pw.len() < 8 {
                return Err(MasterPWError::TooShort);
            }
            // if raw_pw.len() > MAX_MASTER_PW_LEN {
            //     return Err(MasterPWError::TooLong);
            // }
            if !raw_pw.is_ascii() {
                return Err(MasterPWError::NonAscii);
            }
            Ok( Self{ 0: raw_pw.to_owned() } )
        }
        pub fn as_bytes(&self) -> &[u8] {
            self.0.as_bytes()
        }
    }
}

pub fn zeroize_slice(bytes: &mut [u8]) {
    bytes.zeroize();
}

pub type MasterKdfKey = [u8; 32];
pub type AesKey = aes_gcm::Key<Aes256Gcm>;
pub fn gen_aes_key() {

}

// secp256k1 곡선의 유효 범위 (N)
const SECP256K1_ORDER: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
    0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
];

fn is_valid_ecies_key(key: &[u8]) -> bool {
    let is_zero = key.iter().all(|&b| b == 0);
    if is_zero { return false; }
    for i in 0..32 {
        if key[i] < SECP256K1_ORDER[i] { return true; }
        if key[i] > SECP256K1_ORDER[i] { return false; }
    }
    false
}

pub fn _manual_zeroize<T>(data: &mut T) {
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
            _manual_zeroize(&mut $var);
        )+
    };
}

#[inline]
fn master_pw_kdf(master_pw: &MasterPW, mut salt: Salt, kdf_out: &mut [u8]) -> () {
    salt[5]=5; salt[10]=10; salt[15]=15; salt[20]=20; salt[25]=25; salt[30]=30;
    for (t, s) in salt.iter_mut().zip(master_pw.as_bytes().iter()) {
        *t ^= *s;
    }
    let params = ParamsBuilder::new()
        .m_cost(65536) // 64MB 지정 (KB 단위)
        .t_cost(8)     // 반복 횟수
        .p_cost(3)     // 병렬 처리 수준
        .build()
        .unwrap();
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        params
    );
    argon2.hash_password_into(master_pw.as_bytes(), salt.as_slice(), kdf_out.as_mut())
        .unwrap();
    salt.zeroize();
}

pub struct EciesKeyPair {pub pk: Box<PublicKey>, pub sk: Box<SecretKey>}
impl EciesKeyPair {
    pub fn new(pk: PublicKey, sk: SecretKey) -> EciesKeyPair {
        EciesKeyPair{ pk: Box::new(pk), sk: Box::new(sk) }
    }
}
pub fn get_ecies_keypair(kdf_key: &MasterKdfKey) -> Result<EciesKeyPair, MasterPWError> {
    let sk = SecretKey::parse(&kdf_key)
        .map_err(|_| MasterPWError::IncorrectPW)?;
    let pk = PublicKey::from_secret_key(&sk);
    Ok(  EciesKeyPair::new(pk, sk) )
}

pub fn check_master_pw_and_login(mut raw_pw: String, mut salt: Salt)
                                 -> Result<(EciesKeyPair, WrappedUserKey), MasterPWError> {
    let mut master_pw = MasterPW::new(&raw_pw)?;
    raw_pw.zeroize();
    let mut kdf_out = MasterKdfKey::default();
    master_pw_kdf(&master_pw, salt, &mut kdf_out);
    let ecies_key_pair = get_ecies_keypair(&kdf_out)?;
    let wrapped_user_key = get_wrapped_user_key(&master_pw, &kdf_out);
    kdf_out.zeroize();
    master_pw.zeroize();
    salt.zeroize();
    Ok( (ecies_key_pair, wrapped_user_key) )
}
pub fn set_master_pw_and_1st_login(mut raw_new_pw: String)
                                   -> Result<(EciesKeyPair, Salt, WrappedUserKey), MasterPWError> {
    let mut salt = Salt::default();
    let mut master_pw = MasterPW::new(&raw_new_pw)?;
    raw_new_pw.zeroize();
    let mut kdf_out = MasterKdfKey::default();
    loop {
        OsRng.fill_bytes(salt.as_mut_slice());
        master_pw_kdf(&master_pw, salt, &mut kdf_out);
        if is_valid_ecies_key(kdf_out.as_ref()) {
            break;
        }
    }
    let ecies_key_pair = get_ecies_keypair(&kdf_out).ok().unwrap();
    let wrapped_user_key = get_wrapped_user_key(&master_pw, &kdf_out);
    kdf_out.zeroize();
    master_pw.zeroize();
    Ok( (ecies_key_pair, salt, wrapped_user_key) )
}
// pub fn change_master_pw(mut raw_new_pw: String)
//                         -> Result<(EciesKeyPair, Salt, WrappedUserKey), MasterPWError> {
//     let mut salt = Salt::default();
//     let mut master_pw = MasterPW::new(&raw_new_pw)?;
//     raw_new_pw.zeroize();
//     let mut kdf_out = MasterKdfKey::default();
//     loop {
//         OsRng.fill_bytes(salt.as_mut_slice());
//         master_pw_kdf(&master_pw, salt, &mut kdf_out);
//         if is_valid_ecies_key(kdf_out.as_ref()) {
//             break;
//         }
//     }
//     let ecies_key_pair = get_ecies_keypair(&kdf_out).ok().unwrap();
//     let wrapped_user_key = get_wrapped_user_key(&master_pw, &kdf_out);
//     kdf_out.zeroize();
//     master_pw.zeroize();
//     Ok( (ecies_key_pair, salt, wrapped_user_key) )
// }
pub fn get_wrapped_user_key(master_pw: &MasterPW, kdf_key: &MasterKdfKey) -> WrappedUserKey {
    let mut hasher1 = Sha256::new();
    hasher1.update(master_pw.as_bytes());
    let mut hasher2 = hasher1.clone();
    let mut tmp = [0u8;32];
    hasher1.finalize_into(GenericArray::from_mut_slice(tmp.as_mut_slice()));
    hasher2.update(&kdf_key);
    hasher2.update(&tmp);
    hasher2.update(&tmp);
    let mut user_key = UserKey::default();
    hasher2.finalize_into(GenericArray::from_mut_slice(user_key.as_mut_slice()));
    tmp.zeroize();
    let wrapped_user_key = wrap_user_key(user_key).unwrap();
    wrapped_user_key
}

pub type EncryptedDB = Vec<u8>;

pub fn encrypt_db(db: &DB, pk: &mut Box<PublicKey>,)
                  -> Result<EncryptedDB, MasterPWError> {
    let serialized = rkyv::to_bytes::<Error>(db).unwrap();
    let encrypted = ecies::encrypt(&pk.serialize(), &serialized).unwrap();

    Ok( encrypted )
}

pub fn decrypt_db(bytes: &[u8], mut sk: Box<SecretKey>,
) -> Result<DB, MasterPWError> {
    let mut decrypted = ecies::decrypt(&bytes, &sk.serialize())
        .map_err(|_| MasterPWError::IncorrectPW)?;
    manual_zeroize!(*sk);
    let db = rkyv::from_bytes::<DB, Error>(&decrypted).unwrap();
    decrypted.zeroize();

    Ok( db )
}