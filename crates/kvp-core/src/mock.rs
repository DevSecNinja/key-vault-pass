//! A file-backed mock [`SecretStore`] for local development and testing.
//!
//! Persists entries to a JSON file so data survives between CLI invocations and
//! web restarts. Selected via the `KVP_MOCK` environment variable / `--mock`
//! flag; it lets you exercise the full CLI and web UX without an Azure
//! subscription or a Microsoft Entra tenant.
//!
//! It is **not** encrypted and is intended purely for local testing.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::error::{Error, Result};
use crate::secret_store::{RawSecret, RawSecretProperties, SecretStore};

/// Default mock vault file name (created in the current directory).
pub const DEFAULT_MOCK_FILE: &str = "kvp-mock-vault.json";

#[derive(Serialize, Deserialize, Clone)]
struct MockSecret {
    value: String,
    #[serde(default)]
    tags: HashMap<String, String>,
    #[serde(with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    updated_at: OffsetDateTime,
}

#[derive(Serialize, Deserialize, Default)]
struct MockData {
    secrets: HashMap<String, MockSecret>,
}

/// A [`SecretStore`] that reads and writes a JSON file on disk.
pub struct FileSecretStore {
    path: PathBuf,
    // Serialises read-modify-write cycles within this process.
    lock: Mutex<()>,
}

impl FileSecretStore {
    /// Create a store backed by `path`.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            lock: Mutex::new(()),
        }
    }

    /// Resolve the mock file from a `KVP_MOCK` value: a path, or `1`/empty for
    /// the [`DEFAULT_MOCK_FILE`] in the current directory.
    pub fn from_env_value(value: &str) -> Self {
        let path = if value.is_empty() || value == "1" || value.eq_ignore_ascii_case("true") {
            PathBuf::from(DEFAULT_MOCK_FILE)
        } else {
            PathBuf::from(value)
        };
        Self::new(path)
    }

    fn load(&self) -> Result<MockData> {
        match std::fs::read(&self.path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|e| Error::Vault(format!("failed to parse mock vault: {e}"))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(MockData::default()),
            Err(e) => Err(Error::Vault(format!("failed to read mock vault: {e}"))),
        }
    }

    fn save(&self, data: &MockData) -> Result<()> {
        let json = serde_json::to_vec_pretty(data)
            .map_err(|e| Error::Vault(format!("failed to serialize mock vault: {e}")))?;
        std::fs::write(&self.path, json)
            .map_err(|e| Error::Vault(format!("failed to write mock vault: {e}")))
    }
}

impl SecretStore for FileSecretStore {
    async fn set_secret(
        &self,
        name: &str,
        value: &str,
        _content_type: &str,
        tags: &HashMap<String, String>,
    ) -> Result<()> {
        let _guard = self.lock.lock().unwrap();
        let mut data = self.load()?;
        let now = OffsetDateTime::now_utc();
        let created_at = data.secrets.get(name).map(|s| s.created_at).unwrap_or(now);
        data.secrets.insert(
            name.to_string(),
            MockSecret {
                value: value.to_string(),
                tags: tags.clone(),
                created_at,
                updated_at: now,
            },
        );
        self.save(&data)
    }

    async fn get_secret(&self, name: &str) -> Result<RawSecret> {
        let _guard = self.lock.lock().unwrap();
        let data = self.load()?;
        match data.secrets.get(name) {
            Some(s) => Ok(RawSecret {
                value: s.value.clone(),
                created_at: Some(s.created_at),
                updated_at: Some(s.updated_at),
            }),
            None => Err(Error::EntryNotFound(name.to_string())),
        }
    }

    async fn delete_secret(&self, name: &str) -> Result<()> {
        let _guard = self.lock.lock().unwrap();
        let mut data = self.load()?;
        if data.secrets.remove(name).is_none() {
            return Err(Error::EntryNotFound(name.to_string()));
        }
        self.save(&data)
    }

    async fn list_secret_properties(&self) -> Result<Vec<RawSecretProperties>> {
        let _guard = self.lock.lock().unwrap();
        let data = self.load()?;
        Ok(data
            .secrets
            .into_iter()
            .map(|(name, s)| RawSecretProperties {
                name,
                tags: s.tags,
                created_at: Some(s.created_at),
                updated_at: Some(s.updated_at),
            })
            .collect())
    }
}
