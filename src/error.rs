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

    #[error("unauthorized")]
    Unauthorized,

    #[error("invalid credentials")]
    InvalidCredentials,

    #[error("email already exists")]
    EmailAlreadyExists,

    #[error("password must be at least 8 characters")]
    PasswordTooShort,

    #[error("password must be at most 128 characters")]
    PasswordTooLong,

    #[error("password is too common")]
    PasswordTooCommon,

    #[error("JWT is not enabled")]
    JwtDisabled,

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
        Self::Internal {
            message: msg.into(),
            source: None,
        }
    }

    pub fn internal_with(
        msg: impl Into<String>,
        source: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self::Internal {
            message: msg.into(),
            source: Some(Box::new(source)),
        }
    }

    pub fn db(
        msg: impl Into<String>,
        source: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self::Db {
            message: msg.into(),
            source: Some(Box::new(source)),
        }
    }
}

impl From<sqlx::Error> for AuthError {
    fn from(e: sqlx::Error) -> Self {
        match &e {
            sqlx::Error::Database(db) if db.constraint().is_some() => Self::Db {
                message: format!("constraint violation: {}", db.constraint().unwrap_or("")),
                source: Some(Box::new(e)),
            },
            _ => Self::db("database error", e),
        }
    }
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, code, message) = match &self {
            AuthError::NotFound => (StatusCode::NOT_FOUND, "not_found", self.to_string()),
            AuthError::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized", self.to_string()),
            AuthError::InvalidCredentials => (
                StatusCode::UNAUTHORIZED,
                "invalid_credentials",
                self.to_string(),
            ),
            AuthError::EmailAlreadyExists => (
                StatusCode::CONFLICT,
                "email_already_exists",
                self.to_string(),
            ),
            AuthError::PasswordTooShort => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "password_too_short",
                self.to_string(),
            ),
            AuthError::PasswordTooLong => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "password_too_long",
                self.to_string(),
            ),
            AuthError::PasswordTooCommon => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "password_too_common",
                self.to_string(),
            ),
            AuthError::JwtDisabled => (StatusCode::BAD_REQUEST, "jwt_disabled", self.to_string()),
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
