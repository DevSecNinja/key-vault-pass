//! HTTP route handlers for the web app.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum::Form;
use kvp_core::auth::StaticTokenCredential;
use kvp_core::model::{GeneratePasswordOptions, PasswordEntry};
use kvp_core::password::generate_password;
use kvp_core::{BackingStore, FileSecretStore, KeyVaultStore, VaultRepository};
use secrecy::ExposeSecret;
use serde::Deserialize;
use time::OffsetDateTime;
use tower_sessions::Session;

use crate::auth;
use crate::state::{AppError, AppState};

// Session keys.
const S_USER_NAME: &str = "user_name";
const S_USER_EMAIL: &str = "user_email";
const S_TOKEN: &str = "kv_token";
const S_TOKEN_EXP: &str = "kv_token_exp";
const S_STATE: &str = "auth_state";
const S_VERIFIER: &str = "pkce_verifier";
const S_CSRF: &str = "csrf";

fn now_unix() -> i64 {
    OffsetDateTime::now_utc().unix_timestamp()
}

/// Return the session's CSRF token, creating one on first use.
async fn csrf_token(session: &Session) -> Result<String, AppError> {
    if let Some(token) = session.get::<String>(S_CSRF).await? {
        return Ok(token);
    }
    let token = oauth2::CsrfToken::new_random().secret().clone();
    session.insert(S_CSRF, token.clone()).await?;
    Ok(token)
}

/// Verify a form-submitted CSRF token against the session's token.
async fn verify_csrf(session: &Session, provided: &str) -> Result<(), AppError> {
    let expected: Option<String> = session.get(S_CSRF).await?;
    match expected {
        Some(token) if !token.is_empty() && token == provided => Ok(()),
        _ => Err(AppError::Internal(anyhow::anyhow!(
            "invalid or missing CSRF token"
        ))),
    }
}

/// Build a repository acting as the signed-in user, or `Unauthorized`.
async fn repository(
    state: &AppState,
    session: &Session,
) -> Result<VaultRepository<BackingStore>, AppError> {
    let token: Option<String> = session.get(S_TOKEN).await?;
    let expires_on: Option<i64> = session.get(S_TOKEN_EXP).await?;
    let (Some(token), Some(expires_on)) = (token, expires_on) else {
        return Err(AppError::Unauthorized);
    };
    if now_unix() >= expires_on {
        return Err(AppError::Unauthorized);
    }

    // Local mock: ignore the (dev) token and use the file-backed store.
    if let Some(path) = &state.mock {
        return Ok(VaultRepository::new(BackingStore::Mock(
            FileSecretStore::new(path.clone()),
        )));
    }

    let expiry = OffsetDateTime::from_unix_timestamp(expires_on)
        .map_err(|e| AppError::Internal(anyhow::anyhow!(e)))?;
    let credential = StaticTokenCredential::new(token, expiry);
    let store = KeyVaultStore::new(state.settings.require_vault_url()?, credential)?;
    Ok(VaultRepository::new(BackingStore::KeyVault(store)))
}

async fn user_context(session: &Session) -> tera::Context {
    let mut ctx = tera::Context::new();
    let name: Option<String> = session.get(S_USER_NAME).await.ok().flatten();
    let email: Option<String> = session.get(S_USER_EMAIL).await.ok().flatten();
    ctx.insert("user_name", &name);
    ctx.insert("user_email", &email);
    ctx
}

#[derive(Deserialize)]
pub struct SearchQuery {
    #[serde(default)]
    q: String,
}

#[derive(Deserialize)]
pub struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

#[derive(Deserialize)]
pub struct EntryForm {
    name: String,
    password: String,
    #[serde(default)]
    username: String,
    #[serde(default)]
    url: String,
    #[serde(default)]
    notes: String,
    #[serde(default)]
    csrf: String,
}

#[derive(Deserialize)]
pub struct CsrfForm {
    #[serde(default)]
    csrf: String,
}

// -- Health ---------------------------------------------------------------

/// Unauthenticated liveness probe for container orchestrators.
pub async fn healthz() -> &'static str {
    "ok"
}

// -- Home & auth ----------------------------------------------------------

pub async fn index(State(state): State<AppState>, session: Session) -> Response {
    let token: Option<String> = session.get(S_TOKEN).await.ok().flatten();
    if token.is_some() {
        return Redirect::to("/entries").into_response();
    }
    let mut ctx = user_context(&session).await;
    ctx.insert("mock", &state.mock.is_some());
    state.render("login.html", &ctx)
}

pub async fn login(State(state): State<AppState>, session: Session) -> Result<Response, AppError> {
    // Mock mode: skip Entra entirely and sign in as a local dev user.
    if state.mock.is_some() {
        session.insert(S_USER_NAME, "Dev User").await?;
        session.insert(S_USER_EMAIL, "dev@localhost").await?;
        session.insert(S_TOKEN, "mock-token").await?;
        session
            .insert(S_TOKEN_EXP, now_unix() + 24 * 60 * 60)
            .await?;
        return Ok(Redirect::to("/entries").into_response());
    }

    let start = auth::start_auth(&state.settings).map_err(AppError::Internal)?;
    session.insert(S_STATE, start.csrf_state).await?;
    session.insert(S_VERIFIER, start.pkce_verifier).await?;
    Ok(Redirect::to(&start.redirect_url).into_response())
}

pub async fn callback(
    State(state): State<AppState>,
    session: Session,
    Query(query): Query<CallbackQuery>,
) -> Result<Response, AppError> {
    if let Some(error) = query.error {
        let description = query.error_description.unwrap_or(error);
        return Err(AppError::Internal(anyhow::anyhow!(
            "sign-in failed: {description}"
        )));
    }

    let expected_state: Option<String> = session.remove(S_STATE).await?;
    let verifier: Option<String> = session.remove(S_VERIFIER).await?;
    let (Some(code), Some(returned_state), Some(expected_state), Some(verifier)) =
        (query.code, query.state, expected_state, verifier)
    else {
        return Err(AppError::Internal(anyhow::anyhow!(
            "missing or expired authorization state"
        )));
    };
    if returned_state != expected_state {
        return Err(AppError::Internal(anyhow::anyhow!(
            "state mismatch; possible CSRF"
        )));
    }

    let tokens = auth::exchange_code(&state.settings, &state.http, &code, &verifier)
        .await
        .map_err(AppError::Internal)?;

    let (name, email) = tokens
        .id_token
        .as_deref()
        .map(auth::claims_from_id_token)
        .unwrap_or_else(|| ("user".into(), String::new()));

    session.insert(S_USER_NAME, name).await?;
    session.insert(S_USER_EMAIL, email).await?;
    session.insert(S_TOKEN, tokens.access_token).await?;
    session
        .insert(S_TOKEN_EXP, now_unix() + tokens.expires_in.max(0))
        .await?;

    Ok(Redirect::to("/entries").into_response())
}

pub async fn logout(session: Session) -> Result<Response, AppError> {
    session.flush().await?;
    Ok(Redirect::to("/").into_response())
}

// -- Entries --------------------------------------------------------------

pub async fn list_entries(
    State(state): State<AppState>,
    session: Session,
    Query(query): Query<SearchQuery>,
) -> Result<Response, AppError> {
    let repo = repository(&state, &session).await?;
    let filter = if query.q.is_empty() {
        None
    } else {
        Some(query.q.as_str())
    };
    let entries = repo.list_entries(filter).await?;

    let mut ctx = user_context(&session).await;
    ctx.insert("entries", &entries);
    ctx.insert("query", &query.q);
    Ok(state.render("entries.html", &ctx))
}

pub async fn new_entry(
    State(state): State<AppState>,
    session: Session,
) -> Result<Response, AppError> {
    // Ensure the user is authenticated before showing the form.
    repository(&state, &session).await?;
    let csrf = csrf_token(&session).await?;
    let mut ctx = user_context(&session).await;
    ctx.insert("csrf", &csrf);
    ctx.insert(
        "suggested_password",
        &generate_password(&GeneratePasswordOptions::default())?,
    );
    Ok(state.render("edit.html", &ctx))
}

pub async fn create_entry(
    State(state): State<AppState>,
    session: Session,
    Form(form): Form<EntryForm>,
) -> Result<Response, AppError> {
    let repo = repository(&state, &session).await?;
    verify_csrf(&session, &form.csrf).await?;
    let entry = PasswordEntry::new(
        form.name.trim(),
        form.password,
        opt(form.username),
        opt(form.url),
        opt(form.notes),
    )?;
    repo.set_entry(&entry, false).await?;
    Ok(Redirect::to(&format!("/entries/{}", entry.name)).into_response())
}

pub async fn entry_detail(
    State(state): State<AppState>,
    session: Session,
    Path(name): Path<String>,
) -> Result<Response, AppError> {
    let repo = repository(&state, &session).await?;
    let entry = repo.get_entry(&name).await?;
    let csrf = csrf_token(&session).await?;

    // The password is intentionally NOT sent with the page; it is fetched on
    // demand from `/entries/{name}/reveal` only when the user asks for it.
    let mut ctx = user_context(&session).await;
    ctx.insert("name", &entry.name);
    ctx.insert("username", &entry.username);
    ctx.insert("url", &entry.url);
    ctx.insert("notes", &entry.notes);
    ctx.insert("csrf", &csrf);
    ctx.insert(
        "updated_at",
        &entry.updated_at.map(|d| d.date().to_string()),
    );
    Ok(state.render("detail.html", &ctx))
}

/// Return an entry's password as plain text, only when explicitly requested
/// (backs the "Show"/"Copy" controls). Requires an authenticated session.
pub async fn reveal_password(
    State(state): State<AppState>,
    session: Session,
    Path(name): Path<String>,
) -> Result<Response, AppError> {
    let repo = repository(&state, &session).await?;
    let entry = repo.get_entry(&name).await?;
    Ok((
        StatusCode::OK,
        [("cache-control", "no-store")],
        entry.password.expose_secret().to_string(),
    )
        .into_response())
}

pub async fn delete_entry(
    State(state): State<AppState>,
    session: Session,
    Path(name): Path<String>,
    Form(form): Form<CsrfForm>,
) -> Result<Response, AppError> {
    let repo = repository(&state, &session).await?;
    verify_csrf(&session, &form.csrf).await?;
    repo.delete_entry(&name).await?;
    Ok(Redirect::to("/entries").into_response())
}

fn opt(value: String) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}
