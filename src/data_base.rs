use std::borrow::Borrow;
use crate::user_secrets::{decrypt_user_pw, encryt_user_pw, EncryptdUsrPW, WrappedUserKey};
pub use site_name::{SiteName, SiteNameError};
use std::collections::{BTreeMap, HashMap};
use std::ops::Bound;
pub use user_id::{UserID, UserIDError};
pub use user_pw::{UserPW, UserPWError};
use zeroize::Zeroize;

pub mod user_pw {
    use rkyv::{Archive, Deserialize, Serialize};
    use std::error::Error;
    use std::fmt::{Display, Formatter};
    use zeroize::{Zeroize, ZeroizeOnDrop};

    #[derive(Zeroize, ZeroizeOnDrop)]
    #[derive(Archive, Serialize, Deserialize, PartialEq, Eq, Debug, Ord, PartialOrd)]
    #[rkyv(derive(PartialEq, Eq, PartialOrd, Ord))]
    pub struct UserPW (pub String);
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

            Ok( Self {0: trimmed.to_string()} )
        }
        pub(crate) fn void() -> Self {
            Self {0: String::new()}
        }
    }
    impl Display for UserPWError {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            match self {
                UserPWError::Empty => write!(f, "Password is empty"),
            }
        }
    }
    impl Error for UserPWError {}
}

pub mod user_id {
    use rkyv::{Archive, Deserialize, Serialize};
    use std::error::Error;
    use std::fmt::{Display, Formatter};
    use zeroize::{Zeroize, ZeroizeOnDrop};

    const MAX_USER_ID_LEN: usize = 32;
    #[derive(Zeroize, ZeroizeOnDrop)]
    #[derive(Archive, Serialize, Deserialize, PartialEq, Eq, Debug, Ord, PartialOrd)]
    #[rkyv(derive(PartialEq, Eq, PartialOrd, Ord, Hash))]
    #[derive(Hash)]
pub struct UserID (pub String);

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

            Ok( Self { 0: trimmed.to_string() } )
        }
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
}


pub mod site_name {
    use rkyv::{Archive, Deserialize, Serialize};
    use std::error::Error;
    use std::fmt::{Display, Formatter};
    use url::Url;
    use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

    #[derive(Zeroize, ZeroizeOnDrop)]
    #[derive(Archive, Serialize, Deserialize, PartialEq, Eq, Debug, Ord, PartialOrd, Clone)]
    #[rkyv(derive(PartialEq, Eq, PartialOrd, Ord))]
    pub struct SiteName (pub String);
    #[derive(Debug)]
    pub enum SiteNameError {
        Empty,
        ContainsWhitespace,
        InvalidUrl(String),
        InvalidHost,
    }
    impl SiteName {
        pub fn new(input: &str) -> Result<SiteName, SiteNameError> {
            if input.trim().is_empty() {
                return Err(SiteNameError::Empty);
            }
            if input.chars().any(|c| c.is_whitespace()) {
                Err(SiteNameError::ContainsWhitespace)?;
            }
            let with_scheme = Zeroizing::new(
                if input.contains("://") {
                    input.to_string()
                } else {
                    format!("dummy://{}", input)
                }
            );
            let url =
                Url::parse(&with_scheme)
                    .map_err(|err| SiteNameError::InvalidUrl(err.to_string()))?;
            let host = url.host_str()
                .ok_or(SiteNameError::InvalidHost)?;
            let mut normalized = String::new();
            normalized.reserve_exact(input.trim().len());
            normalized.push_str(host);
            if let Some(port) = url.port() {
                normalized.push(':');
                normalized.push_str(&port.to_string());
            }
            if !url.path().is_empty() && url.path() != "/" {
                normalized.push_str(url.path());
            }
            if let Some(q) = url.query() {
                normalized.push('?');
                normalized.push_str(q);
            }
            if let Some(f) = url.fragment() {
                normalized.push('#');
                normalized.push_str(f);
            }
            Ok( Self {0: normalized} )
        }
        pub fn from_unchecked(input: &str) -> SiteName {
            Self {0: input.trim().to_string().to_lowercase()}
        }
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
                }
            }
        }
    }
    impl Error for SiteNameError {}
}
impl Borrow<[u8]> for SiteName {
    #[inline]
    fn borrow(&self) -> &[u8] {
        self.0.as_bytes()
    }
}
impl Borrow<str> for SiteName {
    #[inline]
    fn borrow(&self) -> &str {
        &self.0
    }
}

pub type DB = BTreeMap<SiteName, HashMap<UserID, EncryptdUsrPW>>;

#[derive(Debug)]
pub enum DBIOError {
    UserNotFound,
    SiteNotFound,
    UserAlreadyExists,
    UserPWEncryptionFailed,
    UserPWDecryptionFailed,
    InvalidSession,
}

pub fn add_password(db: &mut DB, site_name: SiteName, user_id: UserID, user_pw: UserPW, wrapped_key: &WrappedUserKey)
                    -> Result<(), DBIOError> {
    let encryted_pw= encryt_user_pw(&site_name, &user_id, user_pw, &wrapped_key)?;

    let users
        = db.entry(site_name).or_insert_with(HashMap::new);

    match users.entry(user_id) {
        std::collections::hash_map::Entry::Vacant(e) => {
            e.insert(encryted_pw);
            Ok( () )
        }
        std::collections::hash_map::Entry::Occupied(_) => {
            Err(DBIOError::UserAlreadyExists)
        }
    }

}

pub fn change_password(db: &mut DB, site_name: SiteName, user_id: UserID, new_pw: UserPW, wrapped_key: &WrappedUserKey, )
    -> Result<(), DBIOError> {
    let encrypted = encryt_user_pw(&site_name, &user_id, new_pw, &wrapped_key)?;

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

            *pw = encrypted;
            Ok(())
        }
        std::collections::hash_map::Entry::Vacant(_) => {
            Err(DBIOError::UserNotFound)
        }
    }
}

pub fn remove_password(db: &mut DB, site_name: SiteName, user_id: UserID, )
    -> Result<(), DBIOError> {

    let remove_site = {
        let users = match db.entry(site_name.clone()) {
            std::collections::btree_map::Entry::Occupied(e) => e.into_mut(),
            std::collections::btree_map::Entry::Vacant(_) => {
                return Err(DBIOError::SiteNotFound);
            }
        };

        match users.entry(user_id) {
            std::collections::hash_map::Entry::Occupied(e) => {
                e.remove_entry();
                users.is_empty()
            }
            std::collections::hash_map::Entry::Vacant(_) => {
                return Err(DBIOError::UserNotFound);
            }
        }
    };

    if remove_site {
        db.remove(&site_name);
    }

    Ok(())
}

pub fn get_password(db: &DB, site_name: &SiteName, user_id: &UserID, wrapped_key: &WrappedUserKey,
) -> Result<UserPW, DBIOError> {

    let users = db
        .get(site_name)
        .ok_or(DBIOError::SiteNotFound)?;

    let encrypted_pw = users
        .get(user_id)
        .ok_or(DBIOError::UserNotFound)?;

    let pw = decrypt_user_pw(&site_name, &user_id, encrypted_pw, &wrapped_key, )
        .map_or(Err(DBIOError::UserPWEncryptionFailed), Ok)?;
    Ok( pw )
}


pub fn prefix_range(db: &DB, prefix: String, )
                    -> impl Iterator<Item=(&SiteName, &HashMap<UserID, EncryptdUsrPW>)> {
    let prefix_bytes = prefix.into_bytes();

    db.range::<[u8], _>((
        Bound::Included(prefix_bytes.clone()),
        Bound::Unbounded,
    ))
        .take_while(move |(k, _)| k.0.as_bytes().starts_with(&*prefix_bytes))
}


pub fn explor_db(db: &mut DB, input_site: String, wrapped_key: &WrappedUserKey) {
    let range =  prefix_range(db, input_site);
    for (site, credentials) in range {
        println!("Site: {}\n", site.0.as_str());
        for cred in credentials {
            println!("  user_id: {:?}\n  password: {:?}\n", &cred.0, get_password(db, &site, &cred.0, &wrapped_key).ok());
        }
    }
}
