//! Integration tests for the storage-agnostic core, using an in-memory store.

use std::collections::HashMap;
use std::sync::Mutex;

use kvp_core::error::Error;
use kvp_core::model::{
    validate_entry_name, GeneratePasswordOptions, PasswordEntry, APP_TAG_KEY, APP_TAG_VALUE,
};
use kvp_core::password::generate_password;
use kvp_core::secret_store::{RawSecret, RawSecretProperties, SecretStore};
use kvp_core::vault::VaultRepository;
use secrecy::ExposeSecret;
use time::OffsetDateTime;

#[derive(Clone)]
struct StoredSecret {
    value: String,
    tags: HashMap<String, String>,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
}

#[derive(Default)]
struct FakeSecretStore {
    secrets: Mutex<HashMap<String, StoredSecret>>,
}

impl SecretStore for FakeSecretStore {
    async fn set_secret(
        &self,
        name: &str,
        value: &str,
        _content_type: &str,
        tags: &HashMap<String, String>,
    ) -> kvp_core::Result<()> {
        let now = OffsetDateTime::now_utc();
        let mut map = self.secrets.lock().unwrap();
        let created_at = map.get(name).map(|s| s.created_at).unwrap_or(now);
        map.insert(
            name.to_string(),
            StoredSecret {
                value: value.to_string(),
                tags: tags.clone(),
                created_at,
                updated_at: now,
            },
        );
        Ok(())
    }

    async fn get_secret(&self, name: &str) -> kvp_core::Result<RawSecret> {
        let map = self.secrets.lock().unwrap();
        match map.get(name) {
            Some(s) => Ok(RawSecret {
                value: s.value.clone(),
                created_at: Some(s.created_at),
                updated_at: Some(s.updated_at),
            }),
            None => Err(Error::EntryNotFound(name.to_string())),
        }
    }

    async fn delete_secret(&self, name: &str) -> kvp_core::Result<()> {
        let mut map = self.secrets.lock().unwrap();
        if map.remove(name).is_none() {
            return Err(Error::EntryNotFound(name.to_string()));
        }
        Ok(())
    }

    async fn list_secret_properties(&self) -> kvp_core::Result<Vec<RawSecretProperties>> {
        let map = self.secrets.lock().unwrap();
        Ok(map
            .iter()
            .map(|(name, s)| RawSecretProperties {
                name: name.clone(),
                tags: s.tags.clone(),
                created_at: Some(s.created_at),
                updated_at: Some(s.updated_at),
            })
            .collect())
    }
}

fn entry(name: &str, password: &str) -> PasswordEntry {
    PasswordEntry::new(
        name,
        password,
        Some("alice".into()),
        Some("https://example.com".into()),
        Some("some notes".into()),
    )
    .unwrap()
}

#[tokio::test]
async fn set_then_get_roundtrips_all_fields() {
    let repo = VaultRepository::new(FakeSecretStore::default());
    repo.set_entry(&entry("github", "s3cr3t!"), false)
        .await
        .unwrap();

    let got = repo.get_entry("github").await.unwrap();
    assert_eq!(got.name, "github");
    assert_eq!(got.password.expose_secret(), "s3cr3t!");
    assert_eq!(got.username.as_deref(), Some("alice"));
    assert_eq!(got.url.as_deref(), Some("https://example.com"));
    assert_eq!(got.notes.as_deref(), Some("some notes"));
    assert!(got.updated_at.is_some());
}

#[tokio::test]
async fn get_missing_entry_is_not_found() {
    let repo = VaultRepository::new(FakeSecretStore::default());
    match repo.get_entry("nope").await {
        Err(Error::EntryNotFound(name)) => assert_eq!(name, "nope"),
        other => panic!("expected EntryNotFound, got {other:?}"),
    }
}

#[tokio::test]
async fn create_only_rejects_duplicates() {
    let repo = VaultRepository::new(FakeSecretStore::default());
    repo.set_entry(&entry("dup", "a"), true).await.unwrap();
    match repo.set_entry(&entry("dup", "b"), true).await {
        Err(Error::EntryAlreadyExists(name)) => assert_eq!(name, "dup"),
        other => panic!("expected EntryAlreadyExists, got {other:?}"),
    }
    // Without create_only, updating is allowed and bumps the value.
    repo.set_entry(&entry("dup", "b"), false).await.unwrap();
    assert_eq!(
        repo.get_entry("dup")
            .await
            .unwrap()
            .password
            .expose_secret(),
        "b"
    );
}

#[tokio::test]
async fn list_filters_by_tag_and_sorts() {
    let store = FakeSecretStore::default();
    // A foreign secret without the app tag must be ignored by listing.
    store
        .set_secret("foreign", "x", "text/plain", &HashMap::new())
        .await
        .unwrap();
    let repo = VaultRepository::new(store);
    repo.set_entry(&entry("zeta", "1"), false).await.unwrap();
    repo.set_entry(&entry("alpha", "2"), false).await.unwrap();

    let names: Vec<String> = repo
        .list_entries(None)
        .await
        .unwrap()
        .into_iter()
        .map(|s| s.name)
        .collect();
    assert_eq!(names, vec!["alpha", "zeta"]);
}

#[tokio::test]
async fn search_is_case_insensitive_substring() {
    let repo = VaultRepository::new(FakeSecretStore::default());
    repo.set_entry(&entry("GitHub-Prod", "1"), false)
        .await
        .unwrap();
    repo.set_entry(&entry("gitlab", "2"), false).await.unwrap();

    let names: Vec<String> = repo
        .list_entries(Some("git"))
        .await
        .unwrap()
        .into_iter()
        .map(|s| s.name)
        .collect();
    assert_eq!(names, vec!["GitHub-Prod", "gitlab"]);

    let hub: Vec<String> = repo
        .list_entries(Some("HUB"))
        .await
        .unwrap()
        .into_iter()
        .map(|s| s.name)
        .collect();
    assert_eq!(hub, vec!["GitHub-Prod"]);
}

#[tokio::test]
async fn delete_removes_entry() {
    let repo = VaultRepository::new(FakeSecretStore::default());
    repo.set_entry(&entry("temp", "1"), false).await.unwrap();
    repo.delete_entry("temp").await.unwrap();
    assert!(matches!(
        repo.get_entry("temp").await,
        Err(Error::EntryNotFound(_))
    ));
}

#[test]
fn app_tag_constants_are_stable() {
    assert_eq!(APP_TAG_KEY, "app");
    assert_eq!(APP_TAG_VALUE, "key-vault-pass");
}

#[test]
fn name_validation_rules() {
    assert!(validate_entry_name("Valid-Name-123").is_ok());
    assert!(validate_entry_name("").is_err());
    assert!(validate_entry_name("has space").is_err());
    assert!(validate_entry_name("under_score").is_err());
    assert!(validate_entry_name(&"a".repeat(128)).is_err());
    assert!(validate_entry_name(&"a".repeat(127)).is_ok());
}

#[test]
fn from_secret_value_handles_plain_and_json() {
    // Legacy/plain secret -> password-only entry.
    let plain = PasswordEntry::from_secret_value("p", "just-a-password", None, None);
    assert_eq!(plain.password.expose_secret(), "just-a-password");
    assert!(plain.username.is_none());

    // Our JSON payload round-trips metadata.
    let e = PasswordEntry::new("j", "pw", Some("bob".into()), None, None).unwrap();
    let json = e.to_secret_value();
    let parsed = PasswordEntry::from_secret_value("j", &json, None, None);
    assert_eq!(parsed.password.expose_secret(), "pw");
    assert_eq!(parsed.username.as_deref(), Some("bob"));
}

#[test]
fn generated_password_meets_requirements() {
    let opts = GeneratePasswordOptions {
        length: 32,
        ..Default::default()
    };
    let pw = generate_password(&opts).unwrap();
    assert_eq!(pw.chars().count(), 32);
    assert!(pw.chars().any(|c| c.is_ascii_lowercase()));
    assert!(pw.chars().any(|c| c.is_ascii_uppercase()));
    assert!(pw.chars().any(|c| c.is_ascii_digit()));
    assert!(pw.chars().any(|c| "!@#$%^&*()-_=+[]{}".contains(c)));
}

#[test]
fn generate_rejects_empty_charset_and_too_short() {
    let no_classes = GeneratePasswordOptions {
        length: 10,
        use_uppercase: false,
        use_lowercase: false,
        use_digits: false,
        use_symbols: false,
    };
    assert!(generate_password(&no_classes).is_err());

    let too_short = GeneratePasswordOptions {
        length: 2,
        ..Default::default()
    };
    assert!(generate_password(&too_short).is_err());
}
