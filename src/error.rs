use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::json;
use thiserror::Error;

#[allow(dead_code)]
#[derive(Debug, Error)]
#[must_use = "errors must be handled or explicitly ignored with `let _ =`"]
pub enum AuthError {
    #[error("not found")]
    NotFound,

    #[error("unauthorized: {message}")]
    Unauthorized { message: String },

    #[error("internal error: {message}")]
    Internal {
        message: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    #[error("database error: {message}")]
    Db {
        message: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },
}

#[allow(dead_code)]
impl AuthError {
    pub fn internal(msg: impl Into<String>) -> Self {
        Self::Internal { message: msg.into(), source: None }
    }

    pub fn internal_with(msg: impl Into<String>, source: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self::Internal { message: msg.into(), source: Some(Box::new(source)) }
    }

    pub fn db(msg: impl Into<String>, source: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self::Db { message: msg.into(), source: Some(Box::new(source)) }
    }

    pub fn unauthorized(msg: impl Into<String>) -> Self {
        Self::Unauthorized { message: msg.into() }
    }
}

impl From<sqlx::Error> for AuthError {
    fn from(e: sqlx::Error) -> Self {
        Self::db("database error", e)
    }
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, code, message) = match &self {
            AuthError::NotFound => (StatusCode::NOT_FOUND, "not_found", self.to_string()),
            AuthError::Unauthorized { message } => {
                (StatusCode::UNAUTHORIZED, "unauthorized", message.clone())
            }
            AuthError::Internal { .. } | AuthError::Db { .. } => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "an internal error occurred".to_string(),
            ),
        };

        if status == StatusCode::INTERNAL_SERVER_ERROR {
            tracing::error!(error = %self, "internal error");
        }

        (
            status,
            Json(json!({ "error": { "code": code, "message": message } })),
        )
            .into_response()
    }
}
