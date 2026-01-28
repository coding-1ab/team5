use std::collections::BTreeMap;
use std::fmt::{Display, Formatter};
use aes_gcm::{Aes256Gcm, KeyInit};
use aes_gcm::aead::Aead;
use argon2::password_hash::SaltString;
use ecies::PublicKey;
use rkyv::{to_bytes, check_archived_root, Deserialize, AlignedVec, Infallible, archived_root, deserialize};
use rkyv::rancor::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};
use crate::master_secrets::{Salt, CryptoKey};
use crate::data_base::{DB, SiteName};
use crate::header::EncryptedDB;

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





pub fn encrypt_db(db: &DB, pk: &PublicKey,)
    -> Result<EncryptedDB, CryptoError> {
    let serialized = rkyv::to_bytes::<Error>(db).unwrap();
    let encrypted = ecies::encrypt(&pk.serialize(), &serialized).unwrap();

    Ok( encrypted )
}

pub fn decrypt_db(data: &[u8], key: &PublicKey,
) -> Result<DB, CryptoError> {
    let decrypted = ecies::decrypt(&data, &key.serialize()).unwrap();
    let db = rkyv::from_bytes::<DB, Error>(&decrypted).unwrap();

    Ok( db )
}
