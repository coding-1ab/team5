use std::fmt::{Display, Formatter};
use aes_gcm::{Aes256Gcm, KeyInit};
use aes_gcm::aead::Aead;
use argon2::password_hash::SaltString;
use rkyv::{to_bytes, check_archived_root, Deserialize, AlignedVec, Infallible, archived_root};
use zeroize::{Zeroize, ZeroizeOnDrop};
use crate::master_secrets::{Salt, CryptoKey};
use crate::data_base::{DB, SiteName};




#[derive(Debug, Eq, PartialEq)]
pub enum CryptoError {
    InvalidHeader,
    InvalidFormat,
    VersionMismatch,
    InvalidKey,
    EncryptionFailed,
    DecryptionFailed,
    SerializeFailed,
    DeserializeFailed,
}

impl Display for CryptoError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoError::InvalidFormat => write!(f, "Invalid encrypted database format"),
            CryptoError::InvalidHeader => write!(f, "Invalid database header"),
            CryptoError::VersionMismatch => write!(f, "Database version mismatch"),
            CryptoError::InvalidKey => write!(f, "Invalid key"),
            CryptoError::EncryptionFailed => write!(f, "Encryption failed"),
            CryptoError::DecryptionFailed => write!(f, "Failed to decrypt database (wrong key or corrupted data)"),
            CryptoError::DeserializeFailed => write!(f, "Failed to deserialize decrypted database"),
            CryptoError::SerializeFailed => write!(f, "Failed to serialize encrypted database"),
        }
    }
}





// 디버깅 자제
pub fn encrypt_db(
    db: DB,
    key: &CryptoKey,
    salt: Salt,
    nonce: Nonce,
) -> Result<(EncryptedDB, Nonce, Salt), CryptoError> {
    let serialized = rkyv::to_bytes::<_,256>(&db).unwrap();

    let cipher = Aes256Gcm::new_from_slice(key.as_bytes())
        .map_err(|_| CryptoError::InvalidKey)?;
    nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(nonce, serialized.as_ref())
        .map_err(|_| CryptoError::EncryptionFailed)?;

    let header = DbHeader {
        magic: HEADER_MAGIC,
        version: DB_VERSION,
        salt,
        ciphertext_len: ciphertext.len() as CipherTextLen,
        nonce,
    };

    let mut out = Vec::new();
    header.write_to(&mut out);
    out.extend_from_slice(&ciphertext);

    Ok( (out, header.nonce, header.salt) )
}

// 디버깅 자제
pub fn decrypt_db(
    data: &[u8],
    key: &CryptoKey,
) -> Result<(DB, Salt), CryptoError> {
    let (header, body) = DbHeader::parse(data)?;

    if header.version != DB_VERSION {
        return Err(CryptoError::VersionMismatch);
    }

    let ct_len = header.ciphertext_len as CipherTextLen;
    if body.len() < ct_len as usize {
        return Err(CryptoError::InvalidFormat);
    }

    let cipher = Aes256Gcm::new_from_slice(key.as_bytes())
        .map_err(|_| CryptoError::InvalidKey)?;
    let plaintext = cipher
        .decrypt(
            aes_gcm::Nonce::from_slice(&header.nonce.as_bytes()[..ct_len as usize]),
            &body[..ct_len as usize],
        )
        .map_err(|_| CryptoError::DecryptionFailed)?;

    let salt = header.salt.clone();
    drop(header); // header no longer needed


    let archived = unsafe {
        archived_root::<DB>(&plaintext)
    };

    check_archived_root::<DB>(&plaintext)
        .map_err(|_| CryptoError::InvalidFormat)?;

    let db: DB = archived
        .deserialize(&mut Infallible)
        .map_err(|_| CryptoError::DeserializeFailed)?;

    Ok((db, salt))
}
