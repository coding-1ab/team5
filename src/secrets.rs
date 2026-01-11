use crate::{Credential, CredentialMap, SiteName};
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;

pub struct Secrets {
    map: CredentialMap,

}

impl Secrets {
    pub fn new() -> Self {
        Self { map: HashMap::new() }
    }
    pub fn load(path: &str) -> Self {
        let mut file = File::options()
            .create(true)
            .write(true)
            .read(true)
            .open(path).expect("Failed to read file");
        let mut contents = Vec::new();
        file.read_to_end(&mut contents).expect("Failed to read file");
        todo!()
    }
    pub fn store(path: &str) {
        todo!();
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
