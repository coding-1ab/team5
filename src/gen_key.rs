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
pub struct Nonce {
    nonce: [u8; 12]
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

    pub fn as_bytes(&self) -> &[u8] {
        self.salt.as_slice()
    }
}

impl Nonce {
    pub fn new() -> Self { // Noexcept
        let mut n = [0u8; size_of::<Self>()];
        rand::rng().fill_bytes(&mut n);
        Self {nonce: n}
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

pub fn gen_key(raw_pw: String, salt: &Salt, key: &CryptoKey)
// It is guaranteed that exceptions can only be thrown from MasterPW
               -> Result<(), MasterPWError> {
    let pw = MasterPW::new(raw_pw)?;
    let key = CryptoKey::new(pw, salt);
    Ok(())
}

pub fn change_master_pw(mut new_pw: String, mut salt: &Salt, mut key: &CryptoKey)
    -> Result<(), MasterPWError> {
    let new_pw = MasterPW::new(new_pw)?;
    let new_salt = Salt::new();
    let new_key = CryptoKey::new(new_pw, &salt);
    Ok(())

}
