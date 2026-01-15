use std::fmt::{Display, Formatter, /*Write*/};
use std::string::String;
use std::collections::BTreeMap;


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
            SiteNameError::Empty => f.write_str("Site name is empty"),
        }
    }
}


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

pub type DB = BTreeMap<SiteName, Vec<Credential>>;

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum CredentialError {
    UserIdEmpty,
    PasswordEmpty,
    PasswordRuleViolation(String),
}

impl Credential {
    pub fn new(user_id: &str, password: &str) -> Result<Self, CredentialError> {
        if user_id.trim().is_empty() {
            return Err(CredentialError::UserIdEmpty);
        }

        if password.is_empty() {
            return Err(CredentialError::PasswordEmpty);
        }

        let length = password.chars().count();

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
                    if !password.chars().any(|c| chars.contains(&c)) {
                        return Err(CredentialError::PasswordRuleViolation(
                            "Must include at least one special character".to_string(),
                        ));
                    }
                }
            }
        }

        Ok(Self {
            user_id: user_id.to_string(),
            password: password.to_string(),
        })
    }
}

impl Display for CredentialError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            CredentialError::UserIdEmpty => f.write_str("User ID is empty"),
            CredentialError::PasswordEmpty => f.write_str("Password is empty"),
            CredentialError::PasswordRuleViolation(msg) => {
                write!(f, "Password rule violation: {}", msg)
            }
        }
    }
}

pub fn prefix_range(
    db: &DB,
    input: String,
) -> impl Iterator<Item = (&SiteName, &Vec<Credential>)> {
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