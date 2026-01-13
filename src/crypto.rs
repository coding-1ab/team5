use std::collections::HashMap;
use aes_gcm::{aead::Aead, Aes256Gcm, Error as AesError, Key, KeyInit, Nonce};
use rand::RngCore;
use rkyv::rancor::Error as RkyvError;
use crate::{Credential, CredentialMap, SiteName};

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

pub fn decrypt_map(data: &[u8], key_bytes: &[u8; 32]) -> Result<CredentialMap, AesError> {
    let (nonce_bytes, ciphertext) = data.split_at(12);

    let key = Key::<Aes256Gcm>::from_slice(key_bytes);
    let cipher = Aes256Gcm::new(key);

    let nonce = Nonce::from_slice(nonce_bytes);
    let decrypted = cipher.decrypt(nonce, ciphertext)?;

    let decrypted =
        rkyv::from_bytes::<Vec<(SiteName, Credential)>, RkyvError>(decrypted.as_slice()).unwrap();
    Ok(HashMap::from_iter(decrypted))
}

#[cfg(test)]
mod tests {
    use crate::crypto::decrypt_map;
    use crate::crypto::encrypt_map;
    use crate::crypto::Credential;
    use crate::crypto::CredentialMap;
    use crate::crypto::SiteName;
    use crate::str32::FixedStr32;

    #[test]
    fn test_crypto() {
        let mut map = CredentialMap::new();
        let credential = Credential {
            id: FixedStr32::new("user1", &[]).unwrap(),
            password: FixedStr32::new("passwd123", &[]).unwrap(),
        };
        map.insert(SiteName(FixedStr32::new("naver", &[]).unwrap()), credential);

        let master_passwd: MasterPassword = {Bytes: [1,2,3,4,5,6,7,8], Length: 8};
        let wrong_password: MasterPassword = {Bytes: [1,1,1,1,1,1,1,1], Length: 8};

        let encrypted = encrypt_map(map.clone(), &master_passwd);

        let correct = decrypt_map(&encrypted, &master_passwd).unwrap();
        let wrong = decrypt_map(&encrypted, &wrong_password);
        assert_eq!(correct, map);
        assert!(wrong.is_err());
    }
}
