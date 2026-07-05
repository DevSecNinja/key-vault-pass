//! Domain models mapping password entries to Key Vault secrets.

use secrecy::{ExposeSecret, SecretString};
use serde::Serialize;
use time::OffsetDateTime;

use crate::error::{Error, Result};

/// Tag marker distinguishing entries this app manages from other vault secrets.
pub const APP_TAG_KEY: &str = "app";
pub const APP_TAG_VALUE: &str = "key-vault-pass";

/// Content type recorded on managed secrets.
pub const CONTENT_TYPE: &str = "application/json;profile=key-vault-pass";

const MAX_NAME_LEN: usize = 127;

/// Validate an entry name against Key Vault secret naming rules
/// (`^[0-9A-Za-z-]{1,127}$`).
pub fn validate_entry_name(name: &str) -> Result<()> {
    let valid = !name.is_empty()
        && name.len() <= MAX_NAME_LEN
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-');
    if valid {
        Ok(())
    } else {
        Err(Error::InvalidEntryName(format!(
            "{name:?}: use 1-127 characters from letters, digits and dashes"
        )))
    }
}

/// A full password entry, including its secret value.
///
/// The password is held in a [`SecretString`] so it is never accidentally
/// logged (its `Debug` is redacted) and is zeroized from memory on drop.
#[derive(Clone, Debug)]
pub struct PasswordEntry {
    pub name: String,
    pub password: SecretString,
    pub username: Option<String>,
    pub url: Option<String>,
    pub notes: Option<String>,
    pub created_at: Option<OffsetDateTime>,
    pub updated_at: Option<OffsetDateTime>,
}

/// Serializable JSON payload stored as the Key Vault secret value.
#[derive(Serialize)]
struct SecretPayload<'a> {
    password: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    username: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    url: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    notes: Option<&'a str>,
}

fn non_empty(value: &Option<String>) -> Option<&str> {
    value.as_deref().filter(|s| !s.is_empty())
}

impl PasswordEntry {
    /// Construct a new entry, validating the name.
    pub fn new(
        name: impl Into<String>,
        password: impl Into<String>,
        username: Option<String>,
        url: Option<String>,
        notes: Option<String>,
    ) -> Result<Self> {
        let name = name.into();
        validate_entry_name(&name)?;
        Ok(Self {
            name,
            password: SecretString::from(password.into()),
            username,
            url,
            notes,
            created_at: None,
            updated_at: None,
        })
    }

    /// Serialise the secret payload (metadata + password) to compact JSON.
    pub fn to_secret_value(&self) -> String {
        let payload = SecretPayload {
            password: self.password.expose_secret(),
            username: non_empty(&self.username),
            url: non_empty(&self.url),
            notes: non_empty(&self.notes),
        };
        // Serialising a fixed struct of owned data cannot fail.
        serde_json::to_string(&payload).expect("serialize secret payload")
    }

    /// Build an entry from a Key Vault secret value.
    ///
    /// Values that are not our JSON payload (e.g. secrets created elsewhere)
    /// are treated as a password-only entry so the tool degrades gracefully.
    pub fn from_secret_value(
        name: impl Into<String>,
        value: &str,
        created_at: Option<OffsetDateTime>,
        updated_at: Option<OffsetDateTime>,
    ) -> Self {
        let name = name.into();
        let mut password = value.to_string();
        let (mut username, mut url, mut notes) = (None, None, None);

        if let Ok(serde_json::Value::Object(map)) = serde_json::from_str::<serde_json::Value>(value)
        {
            if let Some(p) = map.get("password").and_then(|v| v.as_str()) {
                password = p.to_string();
                username = map
                    .get("username")
                    .and_then(|v| v.as_str())
                    .map(str::to_string);
                url = map.get("url").and_then(|v| v.as_str()).map(str::to_string);
                notes = map
                    .get("notes")
                    .and_then(|v| v.as_str())
                    .map(str::to_string);
            }
        }

        Self {
            name,
            password: SecretString::from(password),
            username,
            url,
            notes,
            created_at,
            updated_at,
        }
    }
}

/// Lightweight listing item that never exposes the secret value.
#[derive(Clone, Debug, Serialize)]
pub struct EntrySummary {
    pub name: String,
    #[serde(with = "time::serde::rfc3339::option")]
    pub created_at: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub updated_at: Option<OffsetDateTime>,
}

/// Options controlling password generation.
#[derive(Clone, Debug)]
pub struct GeneratePasswordOptions {
    pub length: usize,
    pub use_uppercase: bool,
    pub use_lowercase: bool,
    pub use_digits: bool,
    pub use_symbols: bool,
}

impl Default for GeneratePasswordOptions {
    fn default() -> Self {
        Self {
            length: 20,
            use_uppercase: true,
            use_lowercase: true,
            use_digits: true,
            use_symbols: true,
        }
    }
}
