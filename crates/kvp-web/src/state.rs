//! Shared application state and error handling for the web app.

use std::path::PathBuf;
use std::sync::Arc;

use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Redirect, Response};
use kvp_core::config::Settings;
use tera::Tera;

/// State shared across all request handlers.
#[derive(Clone)]
pub struct AppState {
    pub settings: Arc<Settings>,
    pub tera: Arc<Tera>,
    pub http: reqwest::Client,
    /// When set, use the local file-backed mock vault and a dev sign-in that
    /// bypasses Microsoft Entra (for local testing only).
    pub mock: Option<PathBuf>,
}

impl AppState {
    /// Render a Tera template into an HTML response.
    pub fn render(&self, template: &str, context: &tera::Context) -> Response {
        match self.tera.render(template, context) {
            Ok(body) => Html(body).into_response(),
            Err(err) => {
                tracing::error!(error = %err, template, "template render failed");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "template render error".to_string(),
                )
                    .into_response()
            }
        }
    }
}

/// Errors returned by handlers, rendered appropriately for a browser.
pub enum AppError {
    /// No valid session — send the user to sign in.
    Unauthorized,
    /// Requested entry was not found.
    NotFound(String),
    /// Any other failure.
    Internal(anyhow::Error),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        match self {
            AppError::Unauthorized => Redirect::to("/auth/login").into_response(),
            AppError::NotFound(msg) => (StatusCode::NOT_FOUND, msg).into_response(),
            AppError::Internal(err) => {
                tracing::error!(error = %err, "request failed");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal server error".to_string(),
                )
                    .into_response()
            }
        }
    }
}

impl From<anyhow::Error> for AppError {
    fn from(err: anyhow::Error) -> Self {
        AppError::Internal(err)
    }
}

impl From<kvp_core::Error> for AppError {
    fn from(err: kvp_core::Error) -> Self {
        match err {
            kvp_core::Error::EntryNotFound(name) => {
                AppError::NotFound(format!("No entry named {name:?}."))
            }
            kvp_core::Error::Authorization => AppError::Unauthorized,
            other => AppError::Internal(anyhow::anyhow!(other)),
        }
    }
}

impl From<tower_sessions::session::Error> for AppError {
    fn from(err: tower_sessions::session::Error) -> Self {
        AppError::Internal(anyhow::anyhow!(err))
    }
}
