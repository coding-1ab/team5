
use bytemuck::{Pod, Zeroable};
use zeroize::Zeroizing;
use crate::file_io::FileIOError;
use crate::master_secrets::RSA_BIT_SIZE;


// const SALT_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const MAGIC_LEN: usize = 8;
const VERSION_DIGITS: usize = 4;
const ENC_AES_KEY_SIZE: usize = RSA_BIT_SIZE / 8;


pub type Magic = [u8; MAGIC_LEN];
pub type Version = [u8; VERSION_DIGITS];
// pub type Salt = [u8; SALT_LEN];
pub type Nonce = Zeroizing<[u8; NONCE_LEN]>;
pub type CipherTextLen = usize;
pub type EncAesKey = [u8; ENC_AES_KEY_SIZE];

/// Program_internal maginc literal
pub const DB_MAGIC: Magic = *b"TeamFive";
/// Program-internal DB format version
pub const DB_VERSION: Version = [0,1,0,0];

pub type EncryptedDB = Vec<u8>;

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub(crate) struct DBHeader {
    magic: Magic,
    version: Version,
    pub(crate) db_nonce: Nonce, // AesKey
    pub(crate) user_nonce: Nonce, // AesKey
    pub(crate) enc_aes_key: EncAesKey,
    pub(crate) ciphertext_len: CipherTextLen,
}
pub const HEADER_LEN: usize = core::mem::size_of::<DBHeader>();

impl DBHeader {
    pub fn parse_header(bytes: &[u8])
                        -> Result<(DBHeader, EncryptedDB), FileIOError> {
        if bytes.len() < HEADER_LEN {
            return Err(FileIOError::InvalidHeader);
        }

        let (head, body) = bytes.split_at(HEADER_LEN);

        let header: DBHeader = *bytemuck::from_bytes::<DBHeader>(head);

        if &header.magic != &DB_MAGIC {
            return Err(FileIOError::InvalidHeader);
        }

        if header.version != DB_VERSION {
            return Err(FileIOError::UnsupportedVersion);
        }

        Ok( (header, body.to_vec()) )
    }

    pub fn write_to(&self, out: &mut Vec<u8>) {
        // out.extend_from_slice(&self.magic);
        // out.extend_from_slice(&self.version.as_bytes());
        // out.extend_from_slice(&self.salt.as_bytes());
        // out.extend_from_slice(&self.ciphertext_len.to_le_bytes());
        // out.extend_from_slice(&self.nonce.as_bytes());
        out.extend_from_slice(bytemuck::bytes_of(&self));
    }
    pub fn empty_valid() -> Self {
        Self {
            magic: DB_MAGIC,
            version: DB_VERSION,
            db_nonce: Nonce::default(),
            user_nonce: Nonce::default(),
            ciphertext_len: 0,
            enc_aes_key: EncAesKey{}
        }
    }
}
unsafe impl Zeroable for DBHeader {}
unsafe impl Pod for DBHeader {}
