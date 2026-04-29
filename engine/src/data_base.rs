use std::arch::x86_64::_mm_clflush;
use crate::user_secrets::{EncryptedUserPW, WrappedSessionKey, decrypt_user_pw, encrypt_user_pw, SessionKeyNonce};
use std::collections::{BTreeMap, HashMap};
use rkyv::{Archive, Deserialize, Serialize};
use std::error::Error;
use std::str::FromStr;

#[derive(
    Archive, Serialize, Deserialize,
    PartialEq, Eq, Debug, Ord, PartialOrd, Clone
)]
#[rkyv(derive(PartialEq, Eq, PartialOrd, Ord))]
pub struct UserPW(pub(crate) String);
#[derive(Debug)]
pub enum UserPWError {
    Empty,
}
impl UserPW {
    #[inline(always)]
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
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}
impl Zeroize for UserPW {
    fn zeroize(&mut self) {
        unsafe { _mm_clflush(self.0.as_mut_ptr()) }
        self.0.zeroize();
    }
}
impl ZeroizeOnDrop for UserPW {}
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
use zeroize::{Zeroize, ZeroizeOnDrop};

// const MAX_USER_ID_LEN: usize = 32;
#[derive(
    Archive, Serialize, Deserialize,
    PartialEq, Eq, Debug, Ord, PartialOrd,
)]
#[rkyv(derive(PartialEq, Eq, PartialOrd, Ord, Hash))]
#[derive(Hash)]
#[derive(Clone)]
pub struct UserID(pub(crate) String);

#[derive(Debug)]
pub enum UserIDError {
    Empty,
    // TooLong,
}
impl UserID {
    #[inline]
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
impl Zeroize for UserID {
    fn zeroize(&mut self) {
        unsafe { _mm_clflush(self.0.as_mut_ptr()) }
        self.0.zeroize();
    }
}
impl ZeroizeOnDrop for UserID {}
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
use url::Url;

#[derive(Archive, Serialize, Deserialize, Debug, Clone, )]
#[rkyv(derive(PartialEq, Eq, PartialOrd, Ord))]
pub struct SiteName {
    pub(crate) full: String,
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
    #[inline]
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
impl Zeroize for SiteName {
    fn zeroize(&mut self) {
        unsafe { _mm_clflush(self.full.as_mut_ptr()) }
        self.full.zeroize();
        unsafe { _mm_clflush(self.reg.as_mut_ptr()) }
        self.reg.zeroize();
    }
}
impl ZeroizeOnDrop for SiteName {}
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

impl Error for DBIOError {}


#[inline(always)]
pub fn add_user_pw(db: &mut DB, site_name: SiteName, user_id: UserID, user_pw: UserPW, wrapped_key: &WrappedSessionKey, user_key_nonce: &SessionKeyNonce)
                   -> Result<(), DBIOError> {
    let encrypted_pw = encrypt_user_pw(&site_name, &user_id, user_pw, wrapped_key, user_key_nonce)?;

    let users = db.entry(site_name)
        .or_insert_with(HashMap::new);

    if users.get(&user_id).is_none() {
        users.insert(user_id, encrypted_pw);
        Ok(())
    } else {
        Err(DBIOError::UserAlreadyExists)
    }
}

#[inline(always)]
pub fn change_user_pw(db: &mut DB, site_name: &SiteName, user_id: &UserID, new_pw: UserPW, wrapped_key: &WrappedSessionKey, user_key_nonce: &SessionKeyNonce)
                      -> Result<(), DBIOError> {
    let users = db.get_mut(site_name)
        .ok_or(DBIOError::SiteNotFound)?;
    let password = users.get_mut(user_id)
        .ok_or(DBIOError::UserNotFound)?;
    password.zeroize();
    *password = encrypt_user_pw(site_name, user_id, new_pw, wrapped_key, user_key_nonce)?;
    Ok(())
}

#[inline(always)]
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

#[inline(always)]
pub fn get_user_pw(db: &DB, site_name: &SiteName, user_id: &UserID, wrapped_key: &WrappedSessionKey, user_key_nonce: &SessionKeyNonce)
                   -> Result<UserPW, DBIOError> {
    let users = db.get(site_name)
        .ok_or(DBIOError::SiteNotFound)?;

    let encrypted_pw = users.get(user_id)
        .ok_or(DBIOError::UserNotFound)?;

    let pw = decrypt_user_pw(&site_name, &user_id, encrypted_pw, &wrapped_key, &user_key_nonce)?;
    
    Ok( pw )
}

#[inline(always)]
pub fn prefix_range<'a>(db: &'a DB, prefix: &str, )
    -> impl Iterator<Item = (&'a SiteName, &'a HashMap<UserID, EncryptedUserPW>)> {
    let lower = SiteName::from_unchecked("", prefix);
    let mut upper_reg = prefix.to_string();
    upper_reg.push(char::MAX);
    let upper = SiteName::from_unchecked("", &upper_reg);

    db.range(lower..upper)
}

pub fn explor_db(db: &mut DB, input_site: String, wrapped_key: &WrappedSessionKey, user_key_nonce: SessionKeyNonce) {
    let range =  prefix_range(db, &*input_site);
    for (site, credentials) in range {
        println!("Site: {}\n", site.as_str());
        for cred in credentials {
            println!(
                "  user_id: {:?}\n  password: {:?}\n",
                &cred.0,
                get_user_pw(db, &site, &cred.0, &wrapped_key, &user_key_nonce).ok()
            );
        }
    }
}

