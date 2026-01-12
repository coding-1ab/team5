use crate::{Credential, CredentialMap, SiteName, crypto};
use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Write};
use aes_gcm::Error  as AesError;


pub struct Secrets {
    map: CredentialMap,

}

impl Secrets {
    pub fn new() -> Self {
        Self { map: HashMap::new() }
    }
    pub fn load(path: &str, key_bytes:&[u8; 32]) ->Result<Self, AesError>{
        let mut file = File::options()
            .create(true)
            .write(true)
            .read(true)
            .open(path).expect("Failed to read file");

        let mut contents = Vec::new();
        file.read_to_end(&mut contents).expect("Failed to read file");

        if contents.is_empty(){
            return Ok(Self::new());
        }
        let map = crypto::decrypt_map(&contents, key_bytes)?;
        
        Ok(Secrets {
            map,
        })
    }
    pub fn store(&self,path: &str, key_bytes:&[u8; 32]) {
        let encrypted = crypto::encrypt_map(self.map.clone(), key_bytes);

        let mut file = File::options()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)
        .expect("Failed to open file for write");

        file.write_all(&encrypted).expect("Failed to write file");
    }

    pub fn insert(&mut self, sitename: SiteName, creds: Credential) {
        self.map.insert(sitename, creds);
    }
    pub fn get(&self, sitename: &SiteName) -> Option<&Credential> {
        self.map.get(sitename)
    }
    pub fn delete(&mut self, sitename: &SiteName) -> bool {
        self.map.remove(sitename).is_some()
    }
}
