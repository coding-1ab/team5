use std::fmt::{Display, Formatter};

use rkyv::{Archive, Deserialize, Serialize};

#[derive(Debug, Eq, PartialEq, Clone)]
pub enum MasterPasswordCreationError {
    Empty,
    TooLong,
    NonAscii,
}

#[derive(Archive, Deserialize, Serialize, Clone, Eq, PartialEq, Hash, Debug)]
#[rkyv(
    compare(PartialEq),
    derive(Debug),
    derive(Hash),
)]
pub struct MasterPassword32 {
    bytes: [u8; 32]
}

impl MasterPassword32 {
    pub fn new(password: &str) -> Result<Self, MasterPasswordCreationError> {
        if password.is_empty() {
            return Err(MasterPasswordCreationError::Empty);
        }

        if !password.is_ascii() {
            return Err(MasterPasswordCreationError::NonAscii);
        }

        let raw = password.as_bytes();

        if raw.len() < 8 {
            return Err(MasterPasswordCreationError::TooShort);
        }

        if raw.len() > 32 {
            return Err(MasterPasswordCreationError::TooLong);
        }

        let mut bytes = [0u8; 32];
        bytes[..raw.len()].copy_from_slice(raw);

        Ok(Self { bytes })
    }

    #[inline]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

impl Display for MasterPasswordCreationError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            MasterPasswordCreationError::Empty => {
                f.write_str("Master password is empty")
            }
            MasterPasswordCreationError::TooShort => {
                f.write_str("Master password must be at least 8 characters long")
            }
            MasterPasswordCreationError::TooLong => {
                f.write_str("Master password length exceeds 32 characters")
            }
            MasterPasswordCreationError::NonAscii => {
                f.write_str("Master password contains non-ASCII characters")
            }
        }
    }
}
