use std::fmt::{Display, Formatter};
use aes_gcm::{
    Aes256Gcm,
    aead::{Aead, Key, KeyInit}
};
use aes_gcm::aes::cipher::BlockEncrypt;
use rand::RngCore;
use rkyv::{to_bytes, check_archived_root, Deserialize, AlignedVec, Infallible, archived_root};
use zeroize::{Zeroize, ZeroizeOnDrop};
use crate::gen_key::{Salt, CryptoKey};
use crate::credential::{DB, SiteName, Credential, CredentialError};


type Magic = [u8; 8];
type Version = u32;
type CipherTextLen = u64;

const HEADER_MAGIC: Magic = *b"TeamFive";
/// Program-internal DB format version
const DB_VERSION: Version = 1;


#[derive(Zeroize, ZeroizeOnDrop)]
struct Nonce {
    pub nonce: [u8; 12]
}

impl Nonce {
    pub fn new() -> Self { // Noexcept
        let mut n = [0u8; size_of::<Self>()];
        rand::rng().fill_bytes(&mut n);
        Self {nonce: n}
    }
    fn from(bytes: [u8; size_of::<Self>()]) -> Self {
        Self {nonce: bytes}
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.nonce
    }
}


pub type EncryptedDB = Vec<u8>;


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
        if input.len() < core::mem::size_of::<Self>() {
            return Err(CryptoError::InvalidFormat);
        }

        let mut offset = 0;

        let mut magic = [0u8; Self::MAGIC_LEN];
        magic.copy_from_slice(&input[offset..offset + Self::MAGIC_LEN]);
        offset += Self::MAGIC_LEN;

        if magic != HEADER_MAGIC {
            return Err(CryptoError::InvalidHeader);
        }

        let version = u32::from_le_bytes(
            input[offset..offset + Self::VERSION_LEN].try_into().unwrap(),
        );
        offset += Self::VERSION_LEN;

        let mut salt = [0u8; Self::SALT_LEN];
        salt.copy_from_slice(&input[offset..offset + Self::SALT_LEN]);
        offset += Self::SALT_LEN;

        let ciphertext_len = u64::from_le_bytes(
            input[offset..offset + Self::CIPHERTEXT_LEN_LEN].try_into().unwrap(),
        );
        offset += Self::CIPHERTEXT_LEN_LEN;

        let mut nonce = [0u8; Self::NONCE_LEN];
        nonce.copy_from_slice(&input[offset..offset + Self::NONCE_LEN]);
        offset += Self::NONCE_LEN;

        Ok((
            Self {
                magic,
                version,
                salt: Salt::from(salt),
                ciphertext_len,
                nonce: Nonce::from(nonce),
            },
            &input[offset..],
        ))
    }

    fn write_to(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.magic);
        out.extend_from_slice(&self.version.to_le_bytes());
        out.extend_from_slice(&self.salt.as_bytes());
        out.extend_from_slice(&self.ciphertext_len.to_le_bytes());
        out.extend_from_slice(&self.nonce.as_bytes());
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
    let ciphertext = cipher
        .encrypt(aes_gcm::Nonce::from_slice(nonce.as_bytes()), serialized.as_ref())
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
