use std::fmt::{Display, Formatter};
use argon2::Argon2;
use rand::{/*Rng,*/ RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum MasterPWError {
    Empty,
    TooShort,
    TooLong,
    NonAscii,
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct MasterPW {
    pw: String
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Salt {
    salt: [u8; 16]
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct CryptoKey {
    key: [u8; 32]
}

impl MasterPW {
    fn new(raw_pw: String) -> Result<Self, MasterPWError> {
        if raw_pw.is_empty() {
            return Err(MasterPWError::Empty);
        }
        if raw_pw.len() < 8 {
            return Err(MasterPWError::TooShort);
        }
        if raw_pw.len() > 32 {
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

impl Salt {
    pub fn new() -> Self { // Noexcept
        let mut s= [0u8; size_of::<Self>()];
        rand::rng().fill_bytes(&mut s);
        Self {salt: s}
    }
    pub fn from(bytes: [u8; size_of::<Self>()]) -> Self {
        Self {salt: bytes}
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.salt.as_slice()
    }
}

impl CryptoKey {
    fn new(pw: MasterPW, salt: &Salt) -> Self {
        let mut key = [0u8; 32];
        let argon2 = Argon2::default();

        argon2
            .hash_password_into(pw.as_bytes(), salt.as_bytes(), &mut key)
            .expect("argon2 failed");

        Self { key }
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.key
    }
}

pub fn gen_key(raw_pw: String, salt: &Salt, key: &mut CryptoKey)
// It is guaranteed that exceptions can only be thrown from MasterPW
    -> Result<(), MasterPWError> {
    let pw = MasterPW::new(raw_pw)?;
    *key = CryptoKey::new(pw, salt);
    Ok(())
}

pub fn change_master_pw(raw_new_pw: String, salt: &mut Salt, key: &mut CryptoKey)
    -> Result<(), MasterPWError> {
    let new_pw = MasterPW::new(raw_new_pw)?;
    *salt = Salt::new();
    *key = CryptoKey::new(new_pw, &salt);
    Ok(())
}
