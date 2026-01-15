use std::fmt::{write, Display, Formatter};
use std::string::String;
use std::collections::BTreeMap;
use std::error::Error;

/// SiteName

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct SiteName {
    name: String
}

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum SiteNameError {
    Empty,
}

impl SiteName {
    pub fn new(raw_input: &String) -> Result<Self, SiteNameError> {
        let input = raw_input.trim();
        if input.is_empty() {
            return Err(SiteNameError::Empty);
        }

        Ok( Self{name: input.to_lowercase()})
    }
    pub fn from_unchecked(input: &String) -> Self {
        Self {name: input.trim().to_lowercase()}
    }

    pub fn as_str(&self) -> &str {
        &self.name
    }


}

impl Display for SiteNameError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            SiteNameError::Empty => write!(f, "Site name is empty"),
        }
    }
}

impl Error for SiteNameError {}


/// Password rules
// (internal default)

#[derive(Debug, Clone, Eq, PartialEq)]
enum PasswordRule {
    MinimumLength(u8),
    IncludeCharacters(&'static [char]),
}

fn default_password_rules() -> &'static [PasswordRule] {
    &[
        PasswordRule::MinimumLength(8),
        PasswordRule::IncludeCharacters(&['!', '@', '#', '$', '%']),
    ]
}

/// Credential

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Credential {
    pub user_id: String,
    pub password: String,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum CredentialError {
    UserIdEmpty,
    PasswordEmpty,
    PasswordRuleViolation(String),
}

impl Credential {
    pub fn new(raw_id: String, raw_pw: String) -> Result<Self, CredentialError> {
        if raw_id.trim().is_empty() {
            return Err(CredentialError::UserIdEmpty);
        }

        if raw_pw.is_empty() {
            return Err(CredentialError::PasswordEmpty);
        }

        let length = raw_pw.len();

        for rule in default_password_rules() {
            match rule {
                PasswordRule::MinimumLength(min) => {
                    if length < *min as usize {
                        return Err(CredentialError::PasswordRuleViolation(
                            format!("Minimum length is {}", min),
                        ));
                    }
                }
                PasswordRule::IncludeCharacters(chars) => {
                    if raw_pw.chars().any(|char| chars.contains(&char)) {
                        return Err(CredentialError::PasswordRuleViolation(
                            "Must include at least one special character".to_string(),
                        ));
                    }
                }
            }
        }

        Ok(Self { user_id: raw_id, password: raw_pw})
    }
}

impl Display for Credential {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "id: {}, password: {}", self.user_id, self.password)
    }
}

impl Display for CredentialError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            CredentialError::UserIdEmpty => write!(f, "User ID is empty"),
            CredentialError::PasswordEmpty => write!(f, "Password is empty"),
            CredentialError::PasswordRuleViolation(msg) => write!(f, "Password rule violation: {}", msg),
        }
    }
}

impl Error for CredentialError {}


pub type DB = BTreeMap<SiteName, Vec<Credential>>;

pub fn add_cred(mut db: &DB, site_name: SiteName, user_id: String, password: String)
    -> Result<(), CredentialError> {
    let cred = Credential::new(user_id, password)?;
    let creds_mut_ref = db.entry(site_name).or_insert(Vec::new());
    let mut iter = std::iter::once(creds_mut_ref);
    if let Some(creds) = iter.next() {
        creds.push(cred);
        ////////
    };
    OK()
}

pub fn change_cred(db: &DB,)
    -> Result<(), CredentialError> {

}

pub fn delete_cred(db: &DB,)
    -> Result<(), CredentialError> {
    // Vec Iter로 먼저 해당 credential 삭제 
    // Map Iter로 해당 Vec의 empty 여부 확인하여 참일 시 키 삭제;
}


pub fn prefix_range(db: &DB, input: String) -> impl Iterator<Item = (&SiteName, &Vec<Credential>)> {
    let start = SiteName::from_unchecked(&input);
    let tmp = format!("{}{}", input, char::MAX);
    let end = SiteName::from_unchecked(&tmp);
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