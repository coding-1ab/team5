use crate::file_io::FileIOError;
use bytemuck::{Pod, Zeroable};

const SALT_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const MAGIC_LEN: usize = 8;
const VERSION_DIGITS: usize = 4;


pub type Magic = [u8; MAGIC_LEN];
pub type Version = [u8; VERSION_DIGITS];
pub type Salt = [u8; SALT_LEN];
pub type Nonce = [u8; NONCE_LEN];
pub type CiphTxtChksum = [u8; 32];
pub type CipherTextLen = usize;

/// Program_internal maginc literal
pub const DB_MAGIC: Magic = *b"TeamFive";
/// Program-internal DB format version
pub const DB_VERSION: Version = [0,1,0,0];

pub type EncryptedDB = Vec<u8>;

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct DBHeader {
    pub(crate) magic: Magic,
    pub(crate) version: Version,
    pub db_salt: Salt, // argon2 salt
    // pub(crate) user_nonce: Nonce,
    pub(crate) ciphertext_checksum: CiphTxtChksum,
    pub(crate) ciphertext_len: CipherTextLen,
}
pub const HEADER_LEN: usize = size_of::<DBHeader>();

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
            return Err(FileIOError::DBVersionMissMatch);
        }

        Ok( (header, body.to_vec()) )
    }

    pub fn write_to(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(bytemuck::bytes_of(self));
    }
    pub fn empty_valid() -> Self {
        Self {
            magic: DB_MAGIC,
            version: DB_VERSION,
            db_salt: Salt::default(), // argon2 slat
            // user_nonce: Nonce::default(),
            ciphertext_checksum: Default::default(),
            ciphertext_len: 0,
        }
    }
}
unsafe impl Zeroable for DBHeader {}
unsafe impl Pod for DBHeader {}
