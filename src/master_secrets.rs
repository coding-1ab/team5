use std::fmt::{Display, Formatter};
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, Key, KeyInit, AeadCore}
};
use rand_chacha::ChaCha20Rng;
// use rand::RngCore::SeedableRng;
// use rand::rngs::OsRng;
// use rand::RngCore;
use rand_core::RngCore;
use rand_core::OsRng;
use argon2::Argon2;
use argon2::password_hash::{PasswordHasher, rand_core, Salt};
use rand_chacha::rand_core::SeedableRng;
use rsa::{RsaPrivateKey, RsaPublicKey, };
use rsa::rand_core::CryptoRngCore;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};
use crate::{ZeroizingString};

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum MasterPWError {
    Empty,
    TooShort,
    TooLong,
    NonAscii,
}

const MAX_MASTER_PW_LEN: usize = 32;
struct MasterPW {
    pw: ZeroizingString
}

impl MasterPW {
    fn new(raw_pw: ZeroizingString) -> Result<Self, MasterPWError> {
        if raw_pw.is_empty() {
            return Err(MasterPWError::Empty);
        }
        if raw_pw.len() < 8 {
            return Err(MasterPWError::TooShort);
        }
        if raw_pw.len() > MAX_MASTER_PW_LEN {
            return Err(MasterPWError::TooLong);
        }
        if !raw_pw.is_ascii() {
            return Err(MasterPWError::NonAscii);
        }
        Ok( Self {pw: raw_pw} )
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.pw.as_bytes()
    }
}

impl Display for MasterPW {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.pw)
    }
}

pub type MasterKdfKey = [u8; 32];
pub type AesKey = aes_gcm::Key<Aes256Gcm>;
pub fn gen_aes_key() {

}

pub const RSA_BIT_SIZE: usize = 4096;
pub type RsaKeys = (RsaPrivateKey, RsaPublicKey);
pub fn gen_rsa_keys(mut master_kdf_key: MasterKdfKey, salt: Salt)
                   -> Result<(RsaKeys), MasterPWError>{
    let mut rng = ChaCha20Rng::from_seed(master_kdf_key);
    master_kdf_key.zeroize();
    let prv_key = RsaPrivateKey::new(&mut rng, RSA_BIT_SIZE)
        .expect("RSA key generation failed");
    let pub_key = RsaPublicKey::from(&prv_key);

}

pub fn master_pw_kdf(raw_pw: ZeroizingString, salt: &SaltString)
                     -> Result<MasterKdfKey, MasterPWError> {
    let pw = MasterPW::new(raw_pw)?;
    let master_kdf_key = MasterKdfKey{};
    let mut rng = OsRng;
    let argon2 = Argon2::default();
    argon2
        .hash_password_into(pw.as_bytes(), salt.as_bytes(), master_kdf_key.as_mut_slice())
        .expect("argon2 failed");
    Ok(master_kdf_key)
}
pub fn _set_master_pw(raw_new_pw: ZeroizingString)
                      -> Result<(), MasterPWError> {
    let mut rng = OsRng;
    let mut salt = Salt::generate(&mut rng);
    let master_kdf_key = master_pw_kdf(raw_new_pw, &mut salt)?;
    let rsa_keys: RsaKeys = gen_rsa_keys(master_kdf_key, salt)?;
    Ok(())
}
