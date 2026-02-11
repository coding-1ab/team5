use crate::user_secrets::{EncryptedUserPW, WrappedUserKey, decrypt_user_pw, encryt_user_pw};
use std::collections::{BTreeMap, HashMap};
use std::ops::{Bound, RangeFrom};
use rkyv::{Archive, Deserialize, Serialize};
use std::error::Error;
use std::str::FromStr;

#[derive(
    Zeroize,
    ZeroizeOnDrop,
    Archive,
    Serialize,
    Deserialize,
    PartialEq,
    Eq,
    Debug,
    Ord,
    PartialOrd,
    Clone
)]
#[rkyv(derive(PartialEq, Eq, PartialOrd, Ord))]
pub struct UserPW(String);
#[derive(Debug)]
pub enum UserPWError {
    Empty,
}
impl UserPW {
    pub fn new(input: &str) -> Result<UserPW, UserPWError> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Err(UserPWError::Empty);
        }

        Ok(Self {
            0: trimmed.to_string(),
        })
    }
    pub fn from_unchecked(input: String) -> Self {
        Self {0: input}
    }
    pub fn void() -> Self {
        Self { 0: String::new() }
    }
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}
impl FromStr for UserPW {
    type Err = UserPWError;
    fn from_str(s: &str) -> Result<Self, UserPWError> { Ok(UserPW::new(s)?) }
}
impl Display for UserPWError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            UserPWError::Empty => write!(f, "Password is empty"),
        }
    }
}
impl Error for UserPWError {}

use std::fmt::{Display, Formatter};
use clap::ValueEnum;
use zeroize::{Zeroize, ZeroizeOnDrop};

// const MAX_USER_ID_LEN: usize = 32;
#[derive(
    Zeroize,
    ZeroizeOnDrop,
    Archive,
    Serialize,
    Deserialize,
    PartialEq,
    Eq,
    Debug,
    Ord,
    PartialOrd,
)]
#[rkyv(derive(PartialEq, Eq, PartialOrd, Ord, Hash))]
#[derive(Hash)]
#[derive(Clone)]
pub struct UserID(String);

#[derive(Debug)]
pub enum UserIDError {
    Empty,
    // TooLong,
}
impl UserID {
    pub fn new(input: &str) -> Result<UserID, UserIDError> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Err(UserIDError::Empty);
        }
        // if trimmed.len() > MAX_USER_ID_LEN {
        //     return Err(UserIDError::TooLong);
        // }

        Ok(Self {
            0: trimmed.to_string(),
        })
    }
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}
impl FromStr for UserID {
    type Err = UserIDError;
    fn from_str(s: &str) -> Result<Self, UserIDError> { Ok(UserID::new(s)?) }
}
impl Display for UserIDError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            UserIDError::Empty => write!(f, "User ID is empty"),
            // UserIDError::TooLong => write!(f, "User ID is too long"),
        }
    }
}
impl Error for UserIDError {}

use std::borrow::Borrow;
use std::cmp::Ordering;
use clap::builder::TypedValueParser;
use url::Url;

#[derive(Zeroize, ZeroizeOnDrop, Archive, Serialize, Deserialize, Debug, Clone, )]
#[rkyv(derive(PartialEq, Eq, PartialOrd, Ord))]
pub struct SiteName {
    full: String,
    pub(crate) reg: String,
}
#[derive(Debug)]
pub enum SiteNameError {
    Empty,
    ContainsWhitespace,
    InvalidUrl(String),
    InvalidHost,
    InvalidDomain,
}

impl SiteName {
    pub fn new(input: &str) -> Result<Self, SiteNameError> {
        if input.trim().is_empty() {
            return Err(SiteNameError::Empty);
        }
        if input.chars().any(|c| c.is_whitespace()) {
            return Err(SiteNameError::ContainsWhitespace);
        }

        let mut with_scheme = if input.contains("://") {
            input.to_owned()
        } else {
            format!("dummy://{}", input)
        };

        let url = Url::parse(&with_scheme)
            .map_err(|e| SiteNameError::InvalidUrl(e.to_string()))?;
        with_scheme.zeroize();

        let host = url.host_str().ok_or(SiteNameError::InvalidHost)?;

        // www canonicalization
        let canonical_full = host.strip_prefix("www.").unwrap_or(host);

        let domain = psl::domain(canonical_full.as_bytes())
            .ok_or(SiteNameError::InvalidDomain)?;

        let reg = std::str::from_utf8(domain.as_bytes())
            .map_err(|_| SiteNameError::InvalidDomain)?
            .to_lowercase();

        Ok(Self {
            full: canonical_full.to_lowercase(),
            reg,
        })
    }
    #[inline(always)]
    pub fn from_unchecked(full: &str, reg: &str) -> Self {
        Self {
            full: full.trim().to_lowercase(),
            reg: reg.trim().to_lowercase(),
        }
    }
    pub fn as_str(&self) -> &str {
        &self.full
    }
}
impl Ord for SiteName {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.reg.cmp(&other.reg) {
            Ordering::Equal => self.full.cmp(&other.full),
            ord => ord,
        }
    }
}
impl PartialOrd for SiteName {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl PartialEq for SiteName {
    fn eq(&self, other: &Self) -> bool {
        self.reg == other.reg && self.full == other.full
    }
}
impl Eq for SiteName {}

impl Borrow<str> for SiteName {
    #[inline]
    fn borrow(&self) -> &str {
        &self.reg
    }
}
impl FromStr for SiteName {
    type Err = SiteNameError;
    fn from_str(s: &str) -> Result<Self, SiteNameError> { Ok(SiteName::new(s)?) }
}
impl Display for SiteNameError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            SiteNameError::Empty => {
                write!(f, "Site name is empty")
            }
            SiteNameError::ContainsWhitespace => {
                write!(f, "Site name must not contain whitespace")
            }
            SiteNameError::InvalidUrl(err) => {
                write!(f, "Site name is not a valid URL or host\nError: {}", err)
            }
            SiteNameError::InvalidHost => {
                write!(f, "Site name does not contain a valid host")
            },
            &SiteNameError::InvalidDomain => {
                write!(f, "Site name does not contain a valid domain")
            }
        }
    }
}
impl Error for SiteNameError {}

pub type DB = BTreeMap<SiteName, HashMap<UserID, EncryptedUserPW>>;

#[derive(Debug)]
pub enum DBIOError {
    UserNotFound,
    SiteNotFound,
    UserAlreadyExists,

    InvalidSession,
}

impl Display for DBIOError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            DBIOError::UserNotFound => {
                write!(f, "User not found")
            }
            DBIOError::SiteNotFound => {
                write!(f, "Site not found")
            }
            DBIOError::UserAlreadyExists => {
                write!(f, "User already exists")
            }
            DBIOError::InvalidSession => {
                write!(f, "Invalid session")
            }
        }
    }
}

// Key zeroize 불가
// pub fn zeroize_db(db: &mut DB) {
//     for (_site, users) in db.iter_mut() {
//         for (_id, pw) in users.iter_mut() {
//             pw.zeroize();
//         }
//         users.clear();
//     }
//     db.clear();
// }

pub fn add_user_pw(db: &mut DB, site_name: SiteName, user_id: UserID, user_pw: UserPW, wrapped_key: &WrappedUserKey)
                   -> Result<(), DBIOError> { //todo 중복 처리
    let encrypted_pw = encryt_user_pw(&site_name, &user_id, user_pw, &wrapped_key)?;

    let users = db.entry(site_name)
        .or_insert_with(HashMap::new);

    match users.entry(user_id) {
        std::collections::hash_map::Entry::Vacant(e) => {
            e.insert(encrypted_pw);
            Ok(())
        }
        std::collections::hash_map::Entry::Occupied(_) => {
            Err(DBIOError::UserAlreadyExists)
        }
    }
}

pub fn change_user_pw(db: &mut DB, site_name: SiteName, user_id: UserID, new_pw: UserPW, wrapped_key: &WrappedUserKey)
                      -> Result<(), DBIOError> {
    let encrypted_pw = encryt_user_pw(&site_name, &user_id, new_pw, &wrapped_key)?;

    let users = match db.entry(site_name) {
        std::collections::btree_map::Entry::Occupied(e) => e.into_mut(),
        std::collections::btree_map::Entry::Vacant(_) => {
            return Err(DBIOError::SiteNotFound);
        }
    };

    match users.entry(user_id) {
        std::collections::hash_map::Entry::Occupied(mut e) => {
            let pw = e.get_mut();

            pw.zeroize();
            *pw = encrypted_pw;
            Ok(())
        }
        std::collections::hash_map::Entry::Vacant(_) => {
            Err(DBIOError::UserNotFound)
        }
    }
}

pub fn remove_user_pw(db: &mut DB, site_name: &SiteName, user_id: &UserID) -> Result<(), DBIOError> {
    let users = db.get_mut(site_name)
        .ok_or(DBIOError::SiteNotFound)?;

    users.remove(user_id)
        .ok_or(DBIOError::UserNotFound)?;

    if users.is_empty() {
        db.remove(site_name);
    }

    Ok(())
}

pub fn get_password(db: &DB, site_name: &SiteName, user_id: &UserID, wrapped_key: &WrappedUserKey)
    -> Result<UserPW, DBIOError> {
    let users = db.get(site_name).ok_or(DBIOError::SiteNotFound)?;

    let encrypted_pw = users.get(user_id).ok_or(DBIOError::UserNotFound)?;

    let pw = decrypt_user_pw(&site_name, &user_id, encrypted_pw, &wrapped_key)
        .map_or(Err(DBIOError::InvalidSession), Ok)?;
    Ok(pw)
}

#[inline]
pub fn prefix_range<'a>(db: &'a DB, prefix: &str, )
    -> impl Iterator<Item = (&'a SiteName, &'a HashMap<UserID, EncryptedUserPW>)> {
    let lower = SiteName::from_unchecked("", prefix);
    let mut upper_reg = prefix.to_string();
    upper_reg.push(char::MAX);
    let upper = SiteName::from_unchecked("", &upper_reg);

    db.range(lower..upper)
}


pub fn explor_db(db: &mut DB, input_site: String, wrapped_key: &WrappedUserKey) {
    let range =  prefix_range(db, &*input_site);
    for (site, credentials) in range {
        println!("Site: {}\n", site.as_str());
        for cred in credentials {
            println!(
                "  user_id: {:?}\n  password: {:?}\n",
                &cred.0,
                get_password(db, &site, &cred.0, &wrapped_key).ok()
            );
        }
    }
}

// #[cfg(test)]
// mod test {
//     use std::collections::HashMap;
//     use crate::data_base::{prefix_range, SiteName, DB};
//
//     #[test]
//     fn test_range() {
//         let mut db = DB::new();
//         db.insert(SiteName::new("naver.com").unwrap(), HashMap::new());
//         db.insert(SiteName::new("daum.net").unwrap(), HashMap::new());
//         db.insert(SiteName::new("google.com").unwrap(), HashMap::new());
//         db.insert(SiteName::new("youtube.com").unwrap(), HashMap::new());
//
//         let mut detected = vec![];
//
//         prefix_range(&db, "g".to_string()).for_each(|(name, _)| {
//             detected.push(name.clone());
//         });
//
//         assert_eq!(detected.len(), 1);
//         assert_eq!(detected.drain(..).next().unwrap(), SiteName::new("google.com").unwrap());
//     }
// }
