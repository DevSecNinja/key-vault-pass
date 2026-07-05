//! A runtime-selectable backing store: real Azure Key Vault or the local mock.
//!
//! `VaultRepository` is generic over [`SecretStore`], but the CLI and web app
//! need to choose their backend at runtime. This enum dispatches to whichever
//! store is active without requiring trait objects (the trait uses `async fn`).

use std::collections::HashMap;

use crate::error::Result;
use crate::keyvault::KeyVaultStore;
use crate::mock::FileSecretStore;
use crate::secret_store::{RawSecret, RawSecretProperties, SecretStore};

/// Either the Azure Key Vault store or the file-backed mock store.
pub enum BackingStore {
    KeyVault(KeyVaultStore),
    Mock(FileSecretStore),
}

impl SecretStore for BackingStore {
    async fn set_secret(
        &self,
        name: &str,
        value: &str,
        content_type: &str,
        tags: &HashMap<String, String>,
    ) -> Result<()> {
        match self {
            BackingStore::KeyVault(s) => s.set_secret(name, value, content_type, tags).await,
            BackingStore::Mock(s) => s.set_secret(name, value, content_type, tags).await,
        }
    }

    async fn get_secret(&self, name: &str) -> Result<RawSecret> {
        match self {
            BackingStore::KeyVault(s) => s.get_secret(name).await,
            BackingStore::Mock(s) => s.get_secret(name).await,
        }
    }

    async fn delete_secret(&self, name: &str) -> Result<()> {
        match self {
            BackingStore::KeyVault(s) => s.delete_secret(name).await,
            BackingStore::Mock(s) => s.delete_secret(name).await,
        }
    }

    async fn list_secret_properties(&self) -> Result<Vec<RawSecretProperties>> {
        match self {
            BackingStore::KeyVault(s) => s.list_secret_properties().await,
            BackingStore::Mock(s) => s.list_secret_properties().await,
        }
    }
}
