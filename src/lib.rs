use std::collections::HashMap;
use rkyv::{Archive, Deserialize, Serialize};
use crate::str32::FixedStr32;

pub mod crypto;
pub mod str32;
pub mod secrets;

pub type CredentialMap = HashMap<SiteName, Credential>;

#[derive(Archive, Deserialize, Serialize, Clone, Eq, PartialEq, Hash, Debug)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct SiteName(FixedStr32);

impl SiteName {
    pub fn new(name: &str) -> SiteName {
        let name = FixedStr32::new(name, &[]).unwrap();
        Self(name)
    }
}

#[derive(Archive, Deserialize, Serialize, Clone, Eq, PartialEq, Hash, Debug)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct Credential {
    id: FixedStr32,
    password: FixedStr32,
}