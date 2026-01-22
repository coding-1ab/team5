use std::borrow::Borrow;
use std::string::String;
use std::collections::{BTreeMap, HashMap};
use rkyv::{Archive, Serialize, Deserialize, Archived, CheckBytes};
use std::error::Error;
use eframe::egui::TextBuffer;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};
pub use user_pw::{UserPW, UserPWError};
pub use user_id::{UserID, UserIDError};
pub use site_name::{SiteName, SiteNameError};
use crate::data_base::site_name::_SiteName;
use crate::data_base::user_id::_UserID;
use crate::user_secrets::{encryt_user_pw, EncUserPW, WrappedUserKey};

pub mod user_pw {
    use std::fmt::{Display, Formatter};
    use std::error::Error;
    use zeroize::Zeroizing;

    pub type UserPW = Zeroizing<String>; /// 외부 입출력용, 수정 금지

    #[derive(Debug)]
    pub enum UserPWError {
        Empty,
    }
    fn new(input: UserPW) -> Result<_UserPW, UserPWError> {
        if input.trim().is_empty() {
            return Err(UserPWError::Empty);
        }
        Ok(input)
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
    use std::fmt::{Display, Formatter};
    use std::error::Error;
    use zeroize::Zeroizing;

    pub type _UserID = String; /// DB 내부 저장용, 복사 금지
    pub type UserID = Zeroizing<String>; /// 외부 입출력용, 수정 금지

    #[derive(Debug)]
    pub enum UserIDError {
        Empty,
    }
    fn new(input: UserID) -> Result<_UserID, UserIDError> {
        if input.trim().is_empty() {
            return Err(UserIDError::Empty);
        }
        Ok( input.to_string() )
    }
    impl Display for UserIDError {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            match self {
                UserIDError::Empty => write!(f, "User ID is empty"),
            }
        }
    }
    impl Error for UserIDError {}
}

pub type DB = BTreeMap<_SiteName, HashMap<_UserID, EncUserPW>>;

pub mod site_name {
    use url::Url;
    use std::fmt::{Display, Formatter};
    use std::error::Error;
    use zeroize::Zeroizing;

    pub type _SiteName = String; /// DB 내부 저장용, 복사 금지
    pub type SiteName = Zeroizing<String>; /// 외부 입출력용, 수정 금지


    #[derive(Debug)]
    pub enum SiteNameError {
        Empty,
        ContainsWhitespace,
        InvalidUrl,
        InvalidHost,
    }

    pub fn validate_and_normalize(input: SiteName) -> Result<_SiteName, SiteNameError> {
        if input.trim().is_empty() {
            return Err(SiteNameError::Empty);
        }
        if input.chars().any(|c| c.is_whitespace()) {
            Err(SiteNameError::ContainsWhitespace)?;
        }
        let with_scheme = if input.contains("://") {
            input.to_string()
        } else {
            format!("dummy://{}", input)
        };
        let url =
            Url::parse(&with_scheme)
                .map_err(|_| SiteNameError::InvalidUrl)?;

        let host = url.host_str().ok_or(SiteNameError::InvalidHost)?;

        let mut normalized = String::new();
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

        Ok( normalized.to_string() )
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
                SiteNameError::InvalidUrl => {
                    write!(f, "Site name is not a valid URL or host")
                }
                SiteNameError::InvalidHost => {
                    write!(f, "Site name does not contain a valid host")
                }
            }
        }
    }
    impl Error for SiteNameError {}
}

pub enum CredentialError {

}

const TMP_WRPD_USR_KEY_A: WrappedUserKey = Zeroizing::new(vec!(0; 32));
pub fn add_credential(db: &mut DB, site_name: SiteName, user_id: UserID, password: UserPW)
    -> Result<(), (UserIDError, UserPWError)> {
    let enc_pw =
        encryt_user_pw(&site_name, &user_id, password, TMP_WRPD_USR_KEY_A);
    let ref_id = db
        .entry(site_name.into_string())
        .or_insert(HashMap::new())
        .or_upwrap();
    *ref_id
        .entry(user_id.into_string())
        .or_insert(enc_pw)
        .or_unwrap();
    

}

// Vec과 String의 재할당시 메모리 이동을 고려하여 zeroize 구현
pub fn change_credential(db: &DB,)
    -> Result<(), CredentialError> {

}
// Vec과 String의 재할당시 메모리 이동을 고려하여 zeroize 구현
pub fn delete_credential(db: &mut DB, site_name: SiteName, credential: &Credential)
    -> Result<(), CredentialError> {
    let ref_vec = db.get_mut(&site_name).unwrap();
    if let Some(pos) = ref_vec.iter()
        .position(|&x| x == credential)

        ref_vec.remove(pos);
        Ok( () )
    }
    // Vec Iter로 먼저 해당 credential 삭제 
    // Map Iter로 해당 Vec의 empty 여부 확인하여 참일 시 키 삭제;
}

pub fn prefix_range(db: &DB, input: String) -> impl Iterator<Item = (&SiteName, &Vec<Credential>)> {
    let start = format!("{}{}", input, char::MAX);
    let end = SiteName::from_unchecked(&start);
    db.range(start..end)
}

#[cfg(test)]
fn explor_db(input_site: String, db: &DB) {
    for (site, credentials) in prefix_range(&db, input_site) {
        println!("Site: {}", site.as_str());
        for cred in credentials {
            println!("  user_id: {}", cred.user_id);
        }
    }
}
