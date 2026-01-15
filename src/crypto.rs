use std::fmt::{Display, Formatter};
use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, KeyInit}
};
use rand::RngCore;
use rkyv::rancor::Error as RkyvError;
use crate::gen_key::Salt;


type Magic = [u8; 4];
type Version = u32;
type CipherTextLen = u64;

const HEADER_MAGIC: Magic = *b"PDB1";
/// Program-internal DB format version
const DB_VERSION: Version = 1;


pub type EncryptedDb = Vec<u8>;


#[derive(Debug, Eq, PartialEq)]
pub enum CryptoError {
    InvalidFormat,
    InvalidHeader,
    VersionMismatch,
    DecryptionFailed,
    DeserializeFailed,
}

impl Display for CryptoError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoError::InvalidFormat =>
                f.write_str("Invalid encrypted database format"),
            CryptoError::InvalidHeader =>
                f.write_str("Invalid database header"),
            CryptoError::VersionMismatch =>
                f.write_str("Database version mismatch"),
            CryptoError::DecryptionFailed =>
                f.write_str("Failed to decrypt database (wrong key or corrupted data)"),
            CryptoError::DeserializeFailed =>
                f.write_str("Failed to deserialize decrypted database"),
        }
    }
}


// ( Crypto.rs-internal struct )

struct DbHeader {
    magic: Magic,
    version: Version,
    salt: Salt,
    ciphertext_len: CipherTextLen,
    nonce: Nonce,
}

impl DbHeader {

    const MAGIC_LEN: usize = size_of::<Magic>();
    const VERSION_LEN: usize = size_of::<Version>();
    const SALT_LEN: usize = size_of::<Salt>();
    const CIPHERTEXT_LEN_LEN: usize = size_of::<CipherTextLen>();
    const NONCE_LEN: usize = size_of::<Nonce>();

    fn parse(input: &[u8]) -> Result<(Self, &[u8]), CryptoError> {
        if input.len() < Self::SIZE {
            return Err(CryptoError::InvalidFormat);
        }

        let mut offset = 0;

        let mut magic = [0u8; 4];
        magic.copy_from_slice(&input[offset..offset + Self::MAGIC_LEN]);
        offset += Self::MAGIC_LEN;

        if magic != HEADER_MAGIC {
            return Err(CryptoError::InvalidHeader);
        }

        let version = u32::from_le_bytes(
            input[offset..offset + Self::VERSION_LEN].try_into().unwrap(),
        );
        offset += Self::VERSION_LEN;

        let mut salt = [0u8; 16];
        salt.copy_from_slice(&input[offset..offset + Self::SALT_LEN]);
        offset += Self::SALT_LEN;

        let ciphertext_len = u64::from_le_bytes(
            input[offset..offset + Self::CIPHERTEXT_LEN_LEN].try_into().unwrap(),
        );
        offset += Self::CIPHERTEXT_LEN_LEN;

        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&input[offset..offset + Self::NONCE_LEN]);
        offset += Self::NONCE_LEN;

        Ok((
            Self {
                magic,
                version,
                salt: Salt::from(salt),
                ciphertext_len,
                nonce,
            },
            &input[offset..],
        ))
    }

    fn write_to(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.magic);
        out.extend_from_slice(&self.version.to_le_bytes());
        out.extend_from_slice(&self.salt);
        out.extend_from_slice(&self.ciphertext_len.to_le_bytes());
        out.extend_from_slice(&self.nonce);
    }
}


pub fn encrypt_db(
    db: CredentialDB,
    key: &CryptoKey256,
) -> (EncryptedDb, Salt) {
    let serialized = rkyv::to_bytes::<RkyvError>(db).unwrap();

    let mut salt = Salt::default();
    rand::thread_rng().fill_bytes(&mut salt);

    let mut nonce = Nonce::default();
    rand::thread_rng().fill_bytes(&mut nonce);

    let cipher = Aes256Gcm::new(Key::from_slice(key.as_bytes()));
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), serialized.as_ref())
        .unwrap();

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

    (out, header.salt)
}


pub fn decrypt_db(
    data: &[u8],
    key: &CryptoKey256,
) -> Result<(CredentialDB, Salt), CryptoError> {
    let (header, body) = DbHeader::parse(data)?;

    if header.version != DB_VERSION {
        return Err(CryptoError::VersionMismatch);
    }

    let ct_len = header.ciphertext_len as CipherTextLen;
    if body.len() < ct_len as usize {
        return Err(CryptoError::InvalidFormat);
    }

    let cipher = Aes256Gcm::new(Key::from_slice(key.as_bytes()));
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&header.nonce),
            &body[..ct_len as usize],
        )
        .map_err(|_| CryptoError::DecryptionFailed)?;

    let salt = header.salt;
    drop(header); // header no longer needed

    let db: CredentialDB =
        rkyv::from_bytes(&plaintext)
            .map_err(|_| CryptoError::DeserializeFailed)?;

    Ok((db, salt))
}
