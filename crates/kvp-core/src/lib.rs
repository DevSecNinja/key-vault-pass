//! key-vault-pass core library.
//!
//! Shared domain logic for the CLI (`kvp`) and web (`kvp-web`) front ends: the
//! password-entry model, a storage-agnostic [`vault::VaultRepository`], the
//! Azure Key Vault–backed [`keyvault::KeyVaultStore`], configuration, password
//! generation and Entra credential helpers.

pub mod auth;
pub mod config;
pub mod error;
pub mod keyvault;
pub mod mock;
pub mod model;
pub mod password;
pub mod secret_store;
pub mod store;
pub mod vault;

pub use config::Settings;
pub use error::{Error, Result};
pub use keyvault::KeyVaultStore;
pub use mock::FileSecretStore;
pub use model::{EntrySummary, GeneratePasswordOptions, PasswordEntry};
pub use password::generate_password;
pub use secret_store::{RawSecret, RawSecretProperties, SecretStore};
pub use store::BackingStore;
pub use vault::VaultRepository;
