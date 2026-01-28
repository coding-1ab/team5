use crate::master_secrets::_manual_zeroize;
use crate::data_base::DB;
use crate::header::EncryptedDB;
use ecies::{PublicKey, SecretKey};
use rkyv::rancor::Error;
use std::fmt::{Display, Formatter};
use zeroize::Zeroize;
use crate::manual_zeroize;

#[derive(Debug, Eq, PartialEq)]
pub enum CryptoError {
    InvalidKey,
    EncryptionFailed,
    DecryptionFailed,
    SerializeFailed,
    DeserializeFailed,
}

impl Display for CryptoError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {

            CryptoError::InvalidKey => write!(f, "Invalid key"),
            CryptoError::EncryptionFailed => write!(f, "Encryption failed"),
            CryptoError::DecryptionFailed => write!(f, "Failed to decrypt database (wrong key or corrupted data)"),
            CryptoError::DeserializeFailed => write!(f, "Failed to deserialize decrypted database"),
            CryptoError::SerializeFailed => write!(f, "Failed to serialize encrypted database"),
        }
    }
}





pub fn encrypt_db(db: &DB, pk: &mut Box<PublicKey>,)
                  -> Result<EncryptedDB, CryptoError> {
    let serialized = rkyv::to_bytes::<Error>(db).unwrap();
    let encrypted = ecies::encrypt(&pk.serialize(), &serialized).unwrap();
    
    Ok( encrypted )
}

pub fn decrypt_db(data: &[u8], mut sk: Box<SecretKey>,
) -> Result<DB, CryptoError> {
    let decrypted = ecies::decrypt(&data, &sk.serialize()).unwrap();
    manual_zeroize!(*sk);
    let db = rkyv::from_bytes::<DB, Error>(&decrypted).unwrap();

    Ok( db )
}
