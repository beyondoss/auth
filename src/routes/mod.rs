pub mod admin;
pub mod authz;
pub mod emails;
pub mod healthz;
pub mod jwks;
pub mod magic_link;
pub mod oauth;
pub mod password_reset;
pub mod sessions;
pub mod tokens;
pub mod totp;
pub mod users;
pub mod webauthn;

use axum::{
    Router, middleware as axum_middleware,
    routing::{delete, get, patch, post, put},
};
use utoipa::OpenApi;
use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};

use crate::{http::AppState, middleware::auth::require_auth};

struct BearerAuth;

impl utoipa::Modify for BearerAuth {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi.components.get_or_insert_with(Default::default);
        components.add_security_scheme(
            "BearerAuth",
            SecurityScheme::Http(
                HttpBuilder::new()
                    .scheme(HttpAuthScheme::Bearer)
                    .bearer_format("session_<id>_<secret>")
                    .build(),
            ),
        );
    }
}

#[derive(OpenApi)]
#[openapi(
    info(
        title = "Beyond Auth",
        version = "1",
        description = "Per-project authentication and authorization service."
    ),
    modifiers(&BearerAuth),
    paths(
        healthz::handler,
        jwks::handler,
        users::signup,
        users::get_me,
        users::update_me,
        sessions::login,
        sessions::list,
        sessions::get_current,
        sessions::delete_current,
        sessions::delete_by_id,
        tokens::issue,
        emails::list,
        emails::add,
        emails::remove,
        emails::make_primary,
        emails::create_verification,
        emails::confirm_verification,
        magic_link::create,
        password_reset::create,
        totp::begin_enrollment,
        totp::confirm_enrollment,
        totp::disable,
        oauth::authorize,
        oauth::callback,
        oauth::apple_callback,
        webauthn::begin_registration,
        webauthn::finish_registration,
        webauthn::list_credentials,
        webauthn::update_credential,
        webauthn::delete_credential,
        webauthn::begin_authentication,
        admin::partitions::ensure_partition,
        authz::check_permission,
        authz::write_relation,
        authz::delete_relation,
        authz::batch_relations,
        authz::get_schema,
        authz::put_schema,
        authz::expand_relation,
        authz::lookup_objects,
        authz::why_check,

    ),
    components(schemas(
        healthz::HealthzResponse,
        jwks::JwkSet,
        jwks::Jwk,
        crate::error::ErrorResponse,
        crate::error::ErrorBody,
        users::SignupRequest,
        users::AuthResponse,
        users::MeResponse,
        users::UserBody,
        users::EmailBody,
        users::TenantBody,
        users::SessionBody,
        crate::users::UpdateUser,
        sessions::LoginRequest,
        sessions::StepUpResponse,
        sessions::SessionsResponse,
        sessions::CurrentSessionResponse,
        crate::sessions::SessionListItem,
        tokens::TokenResponse,
        emails::EmailRecord,
        emails::AddRequest,
        emails::TokenResponse,
        emails::ConfirmVerificationRequest,
        emails::ConfirmVerificationResponse,
        magic_link::CreateRequest,
        magic_link::CreateResponse,
        password_reset::CreateRequest,
        password_reset::CreateResponse,
        totp::EnrollmentResponse,
        totp::ConfirmRequest,
        webauthn::BeginResponse,
        webauthn::RegisteredCredential,
        webauthn::FinishRegistrationRequest,
        webauthn::UpdateCredentialRequest,
        crate::mfa::webauthn::CredentialRecord,
        authz::CheckResponse,
        authz::RelationRequest,
        authz::RelationObject,
        authz::RelationSubject,
        authz::BatchRequest,
        authz::BatchResponse,
        authz::ExpandResponse,
        authz::ExpandSubject,
        authz::LookupResponse,
        authz::TraceResponse,
        crate::authz::schema::AuthzSchema,
        crate::authz::schema::ResourceDef,
        crate::authz::schema::RoleEdge,
        crate::authz::schema::HierarchyDef,
    )),
    tags(
        (name = "system", description = "Health and key material"),
        (name = "users", description = "User registration and profile"),
        (name = "sessions", description = "Session lifecycle and MFA step-up"),
        (name = "tokens", description = "JWT access token issuance"),
        (name = "emails", description = "Email management and verification"),
        (name = "magic-links", description = "Passwordless magic link auth"),
        (name = "password-resets", description = "Password reset flow"),
        (name = "totp", description = "TOTP enrollment and management"),
        (name = "oauth", description = "OAuth 2.0 provider login"),
        (name = "passkeys", description = "Passkey registration and authentication"),
    )
)]
pub struct ApiDoc;

pub fn router(state: AppState) -> Router<AppState> {
    let admin = Router::new()
        .route(
            "/v1/admin/oauth-providers",
            get(admin::oauth::get).put(admin::oauth::put),
        )
        .route(
            "/v1/admin/relation-partitions/{object_type}",
            put(admin::partitions::ensure_partition),
        )
        .route(
            "/v1/authz/relations",
            post(authz::write_relation)
                .delete(authz::delete_relation)
                .patch(authz::batch_relations),
        )
        .route(
            "/v1/authz/schema",
            get(authz::get_schema).put(authz::put_schema),
        )
        .route("/v1/authz/expansions", get(authz::expand_relation))
        .route("/v1/authz/traces", get(authz::why_check))
        .route_layer(axum_middleware::from_fn_with_state(
            state.clone(),
            crate::middleware::admin::require_admin,
        ));

    let public = Router::new()
        .route("/v1/authz/decisions", get(authz::check_permission))
        .route("/healthz", get(healthz::handler))
        .route("/v1/jwks.json", get(jwks::handler))
        .route("/v1/users", post(users::signup))
        .route("/v1/sessions", post(sessions::login))
        .route("/v1/magic-links", post(magic_link::create))
        .route("/v1/oauth/apple/callback", post(oauth::apple_callback))
        .route("/v1/oauth/{provider}", get(oauth::authorize))
        .route("/v1/oauth/{provider}/callback", get(oauth::callback))
        .route("/v1/password-resets", post(password_reset::create))
        // Email verification confirm (unauthenticated — token carries the identity)
        .route(
            "/v1/emails/verifications",
            post(emails::confirm_verification),
        )
        .route(
            "/v1/passkey-authentications",
            post(webauthn::begin_authentication),
        );

    let authenticated = Router::new()
        .route("/v1/users/me", get(users::get_me).patch(users::update_me))
        .route("/v1/sessions", get(sessions::list))
        .route(
            "/v1/sessions/current",
            get(sessions::get_current).delete(sessions::delete_current),
        )
        .route("/v1/sessions/{id}", delete(sessions::delete_by_id))
        .route("/v1/tokens", post(tokens::issue))
        // Email resource
        .route("/v1/emails", get(emails::list).post(emails::add))
        .route(
            "/v1/emails/{id}",
            delete(emails::remove).put(emails::make_primary),
        )
        .route(
            "/v1/emails/{id}/verifications",
            post(emails::create_verification),
        )
        .route(
            "/v1/totp",
            post(totp::begin_enrollment).delete(totp::disable),
        )
        .route("/v1/totp/confirmations", post(totp::confirm_enrollment))
        .route(
            "/v1/passkey-registrations",
            post(webauthn::begin_registration),
        )
        .route(
            "/v1/passkeys",
            get(webauthn::list_credentials).post(webauthn::finish_registration),
        )
        .route(
            "/v1/passkeys/{id}",
            patch(webauthn::update_credential).delete(webauthn::delete_credential),
        )
        .route("/v1/authz/lookups", get(authz::lookup_objects))
        .route_layer(axum_middleware::from_fn_with_state(state, require_auth));

    Router::new()
        .merge(public)
        .merge(authenticated)
        .merge(admin)
}
