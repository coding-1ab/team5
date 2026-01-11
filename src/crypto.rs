use aes_gcm::KeyInit;
use aes_gcm::Nonce;
use aes_gcm::Key;
use aes_gcm::Aes256Gcm;
use aes_gcm::aead::Aead;
use rand::RngCore;
use std::collections::HashMap;
use rkyv::{Archive, Deserialize, Serialize};
use crate::str32::FixedStr32;
use rkyv::rancor::Error as RkyvError;

#[derive(Archive, Deserialize, Serialize, Clone, Eq, PartialEq, Hash)]
#[rkyv(
    compare(PartialEq),
    derive(Debug),
)]
pub struct SiteName(FixedStr32);

#[derive(Archive, Deserialize, Serialize, Clone, Eq, PartialEq, Hash)]
#[rkyv(
    compare(PartialEq),
    derive(Debug),
)]
pub struct Credential {
    id: FixedStr32,
    password: FixedStr32,
}

pub type CredentialMap = HashMap<SiteName, Credential>;

pub fn encrypt_map(map: CredentialMap, key_bytes: &[u8; 32]) -> Vec<u8> {
    let flat: Vec<(SiteName, Credential)> = map.into_iter().collect();
    let serialized = rkyv::to_bytes::<RkyvError>(&flat).unwrap();

    let key = Key::<Aes256Gcm>::from_slice(key_bytes);
    let cipher = Aes256Gcm::new(key);

    let mut nonce_bytes = [0u8; 12];
    let mut rand = rand::rng();
    rand.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let mut encrypted = cipher.encrypt(nonce, serialized.as_ref()).unwrap();

    let mut result = nonce_bytes.to_vec();
    result.append(&mut encrypted);

    result
}

pub fn decrypt_map(data: &[u8], key_bytes: &[u8; 32]) -> CredentialMap {
    let (nonce_bytes, ciphertext) = data.split_at(12);

    let key = Key::<Aes256Gcm>::from_slice(key_bytes);
    let cipher = Aes256Gcm::new(key);

    let nonce = Nonce::from_slice(nonce_bytes);
    let decrypted = cipher.decrypt(nonce, ciphertext).unwrap();

    let decrypted = rkyv::from_bytes::<Vec<(SiteName, Credential)>, RkyvError>(decrypted.as_slice()).unwrap();
    HashMap::from_iter(decrypted)
}
