//! [`VaultRepository`] — maps password entries to Key Vault secrets.
//!
//! This layer is storage-agnostic: it operates purely through the
//! [`SecretStore`] trait, so it is exercised in tests with an in-memory fake
//! and in production with [`crate::keyvault::KeyVaultStore`].

use std::collections::HashMap;

use tracing::info;

use crate::error::{Error, Result};
use crate::model::{
    validate_entry_name, EntrySummary, PasswordEntry, APP_TAG_KEY, APP_TAG_VALUE, CONTENT_TYPE,
};
use crate::secret_store::SecretStore;

/// CRUD operations for password entries, backed by a [`SecretStore`].
pub struct VaultRepository<S: SecretStore> {
    store: S,
}

impl<S: SecretStore> VaultRepository<S> {
    /// Wrap a secret store.
    pub fn new(store: S) -> Self {
        Self { store }
    }

    /// Create or update an entry.
    ///
    /// With `create_only`, returns [`Error::EntryAlreadyExists`] if the name is
    /// already present.
    pub async fn set_entry(&self, entry: &PasswordEntry, create_only: bool) -> Result<()> {
        validate_entry_name(&entry.name)?;
        if create_only && self.exists(&entry.name).await? {
            return Err(Error::EntryAlreadyExists(entry.name.clone()));
        }
        let tags = HashMap::from([(APP_TAG_KEY.to_string(), APP_TAG_VALUE.to_string())]);
        self.store
            .set_secret(&entry.name, &entry.to_secret_value(), CONTENT_TYPE, &tags)
            .await?;
        info!(name = %entry.name, "stored entry");
        Ok(())
    }

    /// Return a full entry by name.
    pub async fn get_entry(&self, name: &str) -> Result<PasswordEntry> {
        validate_entry_name(name)?;
        let secret = self.store.get_secret(name).await?;
        Ok(PasswordEntry::from_secret_value(
            name,
            &secret.value,
            secret.created_at,
            secret.updated_at,
        ))
    }

    /// List managed entries, optionally filtered by a case-insensitive name
    /// substring. Results are sorted by name.
    pub async fn list_entries(&self, query: Option<&str>) -> Result<Vec<EntrySummary>> {
        let needle = query.map(|q| q.to_lowercase());
        let mut summaries: Vec<EntrySummary> = self
            .store
            .list_secret_properties()
            .await?
            .into_iter()
            .filter(|props| props.tags.get(APP_TAG_KEY).map(String::as_str) == Some(APP_TAG_VALUE))
            .filter(|props| match &needle {
                Some(n) => props.name.to_lowercase().contains(n),
                None => true,
            })
            .map(|props| EntrySummary {
                name: props.name,
                created_at: props.created_at,
                updated_at: props.updated_at,
            })
            .collect();
        summaries.sort_by_key(|s| s.name.to_lowercase());
        Ok(summaries)
    }

    /// Delete an entry by name.
    pub async fn delete_entry(&self, name: &str) -> Result<()> {
        validate_entry_name(name)?;
        self.store.delete_secret(name).await?;
        info!(name = %name, "deleted entry");
        Ok(())
    }

    async fn exists(&self, name: &str) -> Result<bool> {
        match self.store.get_secret(name).await {
            Ok(_) => Ok(true),
            Err(Error::EntryNotFound(_)) => Ok(false),
            Err(other) => Err(other),
        }
    }
}
