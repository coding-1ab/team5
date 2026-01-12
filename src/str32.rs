use std::error::Error;
use std::fmt::{Display, Formatter, Write};
use rkyv::{Archive, Deserialize, Serialize};

#[derive(Archive, Deserialize, Serialize, Clone, Eq, PartialEq, Hash, Default, Debug)]
#[rkyv(
    compare(PartialEq),
    derive(Debug),
    derive(Hash),
)]
pub struct FixedStr32 {
    contents: [char; 32],
    length: u8,
}

#[derive(Debug, Eq, PartialEq, Clone)]
pub enum CreationError {
    Empty,
    TooLong,
    RuleViolation(CharacterRule),
}

#[derive(Debug, Eq, PartialEq, Clone)]
pub enum CharacterRule {
    IncludeSpecialCharacters(Vec<char>),
    MinimumLength(u8),
}

impl FixedStr32 {
    pub fn new(contents: &str, rules: &[CharacterRule]) -> Result<Self, CreationError> {
        if contents.is_empty() {
            return Err(CreationError::Empty);
        };

        let length = contents.len();
        if length > 32 {
            return Err(CreationError::TooLong);
        };
        let length = length as u8;

        // implement rule check

        for rule in rules {
            match rule {
                CharacterRule::MinimumLength(min) => {
                    if length < *min {
                        return Err(CreationError::RuleViolation(rule.clone()));
                    }
                }
                CharacterRule::IncludeSpecialCharacters(chars) => {
                    let has_any = contents.chars().any(|c| chars.contains(&c));
                    if !has_any {
                        return Err(CreationError::RuleViolation(rule.clone()));
                    }
                }
            }
        }

        let mut array = [char::default(); 32];
        for (i, c) in contents.chars().enumerate() {
            array[i] = c;
        }

        let created = Self {
            contents: array,
            length,
        };

        Ok(created)
    }

    pub fn length(&self) -> u8 {
        self.length
    }
}

impl Display for FixedStr32 {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        for i in 0..self.length {
            let i = i as usize;
            f.write_char(self.contents[i])?;
        }

        Ok(())
    }
}

impl Display for CreationError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            CreationError::Empty => f.write_str("Empty Password"),
            CreationError::TooLong => f.write_str("Password length is longer than 32"),
            CreationError::RuleViolation(rule) => {
                f.write_str("Rule violation: ")?;
                match rule {
                    CharacterRule::IncludeSpecialCharacters(characters) => {
                        f.write_str("Does not include any of: ")?;
                        for c in characters {
                            f.write_char(*c)?;
                        }
                        Ok(())
                    }
                    CharacterRule::MinimumLength(length) => {
                        f.write_fmt(format_args!("Must be longer than: {}", length))
                    }
                }
            }
        }
    }
}

impl Error for CreationError {}
