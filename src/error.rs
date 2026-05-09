use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use thiserror::Error;
use utoipa::ToSchema;

/// Response extension inserted by `AuthError::into_response` so the metrics
/// middleware can increment `auth_errors_total` without reading the body.
#[derive(Clone)]
pub struct AuthErrorCode(pub &'static str);

/// Wire-format error body returned on all non-2xx responses.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ErrorBody {
    /// Machine-readable error code, e.g. `"invalid_credentials"`.
    pub code: String,
    /// Human-readable description.
    pub message: String,
    /// Optional actionable guidance present on configuration-gate errors.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(nullable)]
    pub hint: Option<String>,
}

/// Top-level error envelope for all API error responses.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ErrorResponse {
    pub error: ErrorBody,
}

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

    #[error("conflict")]
    Conflict,

    #[error("password must be at least 12 characters")]
    PasswordTooShort,

    #[error("password must be at most 128 characters")]
    PasswordTooLong,

    #[error("password is too common")]
    PasswordTooCommon,

    #[error(
        "JWT is not enabled — enable it via PATCH /v1/admin/config with {{\"jwt_enabled\":true}}"
    )]
    JwtDisabled,

    #[error("token is invalid")]
    TokenInvalid,

    #[error("token has expired")]
    TokenExpired,

    #[error("token has already been used")]
    TokenUsed,

    #[error("oauth error: {message}")]
    OAuth { message: String },

    #[error("mfa error: {message}")]
    MfaError { message: String },

    #[error("admin authorization required")]
    AdminRequired,

    #[error("oauth provider is not configured")]
    OAuthProviderNotConfigured,

    #[error("redirect_url is not in the configured allowlist")]
    OAuthRedirectNotAllowed,

    #[error("org not found")]
    OrgNotFound,

    #[error("user is not a member of this org")]
    NotMember,

    #[error("user is already a member of this org")]
    AlreadyMember,

    #[error("cannot remove or demote the last owner")]
    LastOwner,

    #[error("cannot remove the last authentication method")]
    LastIdentity,

    #[error("personal orgs cannot be deleted")]
    PersonalOrg,

    #[error("slug is already taken")]
    SlugConflict,

    #[error("forbidden")]
    Forbidden,

    #[error("bad request: {message}")]
    BadRequest { message: String },

    #[error("cannot remove your only email address")]
    LastEmail,

    #[error(
        "passkeys are not configured — set WEBAUTHN_RP_ID and WEBAUTHN_RP_ORIGIN to enable them"
    )]
    PasskeysNotConfigured,

    #[error("invitation not found or expired")]
    InvitationNotFound,

    #[error("authz is not enabled — PUT /v1/authz/schema to enable it")]
    AuthzNotEnabled,

    #[error("authz schema is invalid: {message}")]
    AuthzSchemaInvalid { message: String },

    #[error("unknown resource type: {resource_type}")]
    AuthzUnknownResource { resource_type: String },

    #[error("unknown permission: {permission}")]
    AuthzUnknownPermission { permission: String },

    /// `message` is emitted verbatim in structured error logs — do not include PII.
    #[error("internal error: {message}")]
    Internal {
        message: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    #[error("database error: {message}")]
    Db {
        message: String,
        /// Constraint name from the database error, if any.
        constraint: Option<String>,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },
}

#[allow(dead_code)]
impl AuthError {
    pub fn bad_request(msg: impl Into<String>) -> Self {
        Self::BadRequest {
            message: msg.into(),
        }
    }

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
            constraint: None,
            source: Some(Box::new(source)),
        }
    }

    fn hint(&self) -> Option<&'static str> {
        match self {
            AuthError::JwtDisabled => {
                Some("Enable JWT issuance via PATCH /v1/admin/config with {\"jwt_enabled\":true}.")
            }
            AuthError::AuthzNotEnabled => Some(
                "Upload an authorization schema via PUT /v1/authz/schema before using authorization endpoints.",
            ),
            _ => None,
        }
    }
}

impl From<sqlx::Error> for AuthError {
    fn from(e: sqlx::Error) -> Self {
        match &e {
            sqlx::Error::Database(db) if db.constraint().is_some() => {
                let constraint = db.constraint().map(str::to_owned);
                Self::Db {
                    message: format!(
                        "constraint violation: {}",
                        constraint.as_deref().unwrap_or("")
                    ),
                    constraint,
                    source: Some(Box::new(e)),
                }
            }
            _ => Self::db("database error", e),
        }
    }
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, code, message) = match &self {
            AuthError::NotFound => (StatusCode::NOT_FOUND, "not_found", self.to_string()),
            AuthError::OrgNotFound => (StatusCode::NOT_FOUND, "org_not_found", self.to_string()),
            AuthError::NotMember => (StatusCode::FORBIDDEN, "not_member", self.to_string()),
            AuthError::AlreadyMember => (StatusCode::CONFLICT, "already_member", self.to_string()),
            AuthError::LastOwner => (StatusCode::CONFLICT, "last_owner", self.to_string()),
            AuthError::LastEmail => (StatusCode::CONFLICT, "last_email", self.to_string()),
            AuthError::LastIdentity => (StatusCode::CONFLICT, "last_identity", self.to_string()),
            AuthError::PersonalOrg => (StatusCode::CONFLICT, "personal_org", self.to_string()),
            AuthError::SlugConflict => (StatusCode::CONFLICT, "slug_conflict", self.to_string()),
            AuthError::Forbidden => (StatusCode::FORBIDDEN, "forbidden", self.to_string()),
            AuthError::BadRequest { .. } => {
                (StatusCode::BAD_REQUEST, "bad_request", self.to_string())
            }
            AuthError::PasskeysNotConfigured => (
                StatusCode::BAD_REQUEST,
                "passkeys_not_configured",
                self.to_string(),
            ),
            AuthError::InvitationNotFound => (
                StatusCode::NOT_FOUND,
                "invitation_not_found",
                self.to_string(),
            ),
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
            AuthError::Conflict => (StatusCode::CONFLICT, "conflict", self.to_string()),
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
            AuthError::TokenInvalid => {
                (StatusCode::UNAUTHORIZED, "token_invalid", self.to_string())
            }
            AuthError::TokenExpired => {
                (StatusCode::UNAUTHORIZED, "token_expired", self.to_string())
            }
            AuthError::TokenUsed => (StatusCode::UNAUTHORIZED, "token_used", self.to_string()),
            AuthError::OAuth { .. } => (StatusCode::BAD_REQUEST, "oauth_error", self.to_string()),
            AuthError::MfaError { .. } => (StatusCode::UNAUTHORIZED, "mfa_error", self.to_string()),
            AuthError::AdminRequired => {
                (StatusCode::UNAUTHORIZED, "admin_required", self.to_string())
            }
            AuthError::OAuthProviderNotConfigured => (
                StatusCode::BAD_REQUEST,
                "oauth_provider_not_configured",
                self.to_string(),
            ),
            AuthError::OAuthRedirectNotAllowed => (
                StatusCode::BAD_REQUEST,
                "oauth_redirect_not_allowed",
                self.to_string(),
            ),
            AuthError::AuthzNotEnabled => (
                StatusCode::BAD_REQUEST,
                "authz_not_enabled",
                self.to_string(),
            ),
            AuthError::AuthzSchemaInvalid { .. } => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "authz_schema_invalid",
                self.to_string(),
            ),
            AuthError::AuthzUnknownResource { .. } => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "authz_unknown_resource",
                self.to_string(),
            ),
            AuthError::AuthzUnknownPermission { .. } => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "authz_unknown_permission",
                self.to_string(),
            ),
            AuthError::Internal { .. } | AuthError::Db { .. } => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "an internal error occurred".to_string(),
            ),
        };

        if status == StatusCode::INTERNAL_SERVER_ERROR {
            tracing::error!(error = %self, "internal error");
        }

        let hint = self.hint();
        let body = match hint {
            Some(h) => json!({ "error": { "code": code, "message": message, "hint": h } }),
            None => json!({ "error": { "code": code, "message": message } }),
        };
        let mut response = (status, Json(body)).into_response();
        response.extensions_mut().insert(AuthErrorCode(code));
        response
    }
}
