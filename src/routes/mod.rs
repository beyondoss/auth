pub mod admin;
pub mod authz;
pub mod emails;
pub mod healthz;
pub mod identities;
pub mod invitations;
pub mod jwks;
pub mod keys;
pub mod magic_link;
pub mod oauth;
pub mod orgs;
pub mod passkeys;
pub mod password_reset;
pub mod sessions;
pub mod tokens;
pub mod totp;
pub mod users;

use axum::{
    Router, middleware as axum_middleware,
    routing::{delete, get, patch, post},
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
        healthz::readyz_handler,
        healthz::livez_handler,
        jwks::handler,
        users::delete_me,
        users::signup,
        users::get_me,
        users::update_me,
        sessions::login,
        sessions::list,
        sessions::delete_all,
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
        totp::regenerate_recovery_codes,
        oauth::authorize,
        oauth::callback,
        oauth::apple_callback,
        passkeys::begin_registration,
        passkeys::finish_registration,
        passkeys::list_credentials,
        passkeys::update_credential,
        passkeys::delete_credential,
        passkeys::begin_authentication,
        orgs::create_org,
        orgs::list_orgs,
        orgs::get_org,
        orgs::update_org,
        orgs::delete_org,
        orgs::list_members,
        orgs::update_member,
        orgs::remove_member,
        orgs::create_invitation,
        orgs::list_invitations,
        orgs::resend_invitation,
        orgs::revoke_invitation,
        identities::list,
        identities::add_password,
        identities::update,
        identities::unlink,
        invitations::view_invitation,
        invitations::accept_invitation,
        invitations::decline_invitation,
        admin::impersonations::create,
        admin::oauth::get,
        admin::oauth::put,
        admin::users::search,
        admin::users::get_by_id,
        admin::users::delete_sessions,
        admin::config::get,
        admin::config::patch,
        keys::create,
        keys::list,
        keys::get,
        keys::delete,
        authz::check_permission,
        authz::post_checks,
        authz::write_relation,
        authz::delete_relation,
        authz::batch_relations,
        authz::get_schema,
        authz::put_schema,
        authz::list_subjects,
        authz::list_subjects_expand,
        authz::list_objects,
        authz::why_check,

    ),
    components(schemas(
        healthz::HealthResponse,
        jwks::JwkSet,
        jwks::Jwk,
        crate::error::ErrorResponse,
        crate::error::ErrorBody,
        users::SignupRequest,
        users::AuthResponse,
        users::MeResponse,
        users::UserBody,
        users::EmailBody,
        users::OrgBody,
        users::SessionBody,
        users::UpdateMeRequest,
        sessions::LoginRequest,
        sessions::StepUpKind,
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
        totp::RecoveryCodesResponse,
        identities::IdentitiesResponse,
        identities::IdentityItem,
        identities::AddPasswordRequest,
        identities::UpdateIdentityRequest,
        oauth::AuthorizeResponse,
        oauth::CallbackResponse,
        oauth::LinkCallbackResponse,
        passkeys::BeginResponse,
        passkeys::RegisteredCredential,
        passkeys::FinishRegistrationRequest,
        passkeys::UpdateCredentialRequest,
        crate::mfa::passkeys::CredentialRecord,
        authz::CheckResponse,
        authz::CheckResult,
        authz::ChecksRequest,
        authz::ChecksItem,
        authz::ChecksResponse,
        authz::BatchDecisionRequest,
        authz::BatchDecisionResponse,
        authz::RelationRequest,
        authz::RelationObject,
        authz::RelationSubject,
        authz::BatchRequest,
        authz::BatchResponse,
        authz::SubjectsResponse,
        authz::Subject,
        authz::ObjectsResponse,
        authz::TraceResponse,
        crate::authz::schema::AuthzSchema,
        crate::authz::schema::ResourceDef,
        crate::authz::schema::HierarchyDef,
        orgs::OrgResponse,
        orgs::OrgsResponse,
        orgs::MemberResponse,
        orgs::MembersResponse,
        orgs::InvitationResponse,
        orgs::InvitationsResponse,
        orgs::CreateOrgRequest,
        orgs::UpdateOrgRequest,
        orgs::UpdateMemberRequest,
        orgs::CreateInvitationRequest,
        invitations::InvitationViewResponse,
        admin::impersonations::ImpersonateRequest,
        admin::oauth::AdminOAuthRequest,
        admin::oauth::AdminOAuthResponse,
        admin::oauth::GithubRedacted,
        admin::oauth::GoogleRedacted,
        admin::oauth::AppleRedacted,
        admin::oauth::MicrosoftRedacted,
        admin::oauth::OidcRedacted,
        admin::users::AdminUserResponse,
        admin::config::UpdateConfigRequest,
        admin::config::ConfigResponse,
        keys::CreateRequest,
        keys::CreateResponse,
        keys::KeysResponse,
        crate::keys::Key,
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
        (name = "identities", description = "Auth method management — list, add password, update, unlink"),
        (name = "orgs", description = "Org management, membership, and invitations"),
        (name = "invitations", description = "Invitation accept and decline"),
        (name = "keys", description = "API key management"),
        (name = "admin", description = "Admin operations"),
    )
)]
pub struct ApiDoc;

pub fn router(state: AppState) -> Router<AppState> {
    let admin = Router::new()
        .route(
            "/v1/admin/impersonations",
            post(admin::impersonations::create),
        )
        .route(
            "/v1/admin/oauth-providers",
            get(admin::oauth::get).put(admin::oauth::put),
        )
        .route("/v1/admin/users", get(admin::users::search))
        .route("/v1/admin/users/{id}", get(admin::users::get_by_id))
        .route(
            "/v1/admin/users/{id}/sessions",
            delete(admin::users::delete_sessions),
        )
        .route(
            "/v1/admin/config",
            get(admin::config::get).patch(admin::config::patch),
        )
        .route("/v1/admin/authz/subjects", get(authz::list_subjects_expand))
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
        .route("/v1/authz/traces", get(authz::why_check))
        .route_layer(axum_middleware::from_fn_with_state(
            state.clone(),
            crate::middleware::admin::require_admin,
        ));

    let public = Router::new()
        .route(
            "/v1/authz/decisions",
            get(authz::check_permission).post(authz::batch_check_permissions),
        )
        .route("/v1/authz/checks", post(authz::post_checks))
        .route("/readyz", get(healthz::readyz_handler))
        .route("/livez", get(healthz::livez_handler))
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
            post(passkeys::begin_authentication),
        )
        // Public invitation endpoints (token in query string carries identity)
        .route("/v1/invitations/{id}", get(invitations::view_invitation))
        .route(
            "/v1/invitations/{id}/declinations",
            post(invitations::decline_invitation),
        )
        // Token endpoint handles its own auth (accepts session, refresh, and API key tokens).
        .route("/v1/tokens", post(tokens::issue));

    let authenticated = Router::new()
        .route(
            "/v1/users/me",
            get(users::get_me)
                .patch(users::update_me)
                .delete(users::delete_me),
        )
        .route(
            "/v1/sessions",
            get(sessions::list).delete(sessions::delete_all),
        )
        .route(
            "/v1/sessions/current",
            get(sessions::get_current).delete(sessions::delete_current),
        )
        .route("/v1/sessions/{id}", delete(sessions::delete_by_id))
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
            "/v1/totp/recovery-codes",
            post(totp::regenerate_recovery_codes),
        )
        .route(
            "/v1/identities",
            get(identities::list).post(identities::add_password),
        )
        .route(
            "/v1/identities/{id}",
            patch(identities::update).delete(identities::unlink),
        )
        .route(
            "/v1/passkey-registrations",
            post(passkeys::begin_registration),
        )
        .route(
            "/v1/passkeys",
            get(passkeys::list_credentials).post(passkeys::finish_registration),
        )
        .route(
            "/v1/passkeys/{id}",
            patch(passkeys::update_credential).delete(passkeys::delete_credential),
        )
        .route("/v1/authz/subjects", get(authz::list_subjects))
        .route("/v1/authz/objects", get(authz::list_objects))
        .route("/v1/keys", get(keys::list).post(keys::create))
        .route("/v1/keys/{id}", get(keys::get).delete(keys::delete))
        // Org management
        .route("/v1/orgs", get(orgs::list_orgs).post(orgs::create_org))
        .route(
            "/v1/orgs/{id}",
            get(orgs::get_org)
                .patch(orgs::update_org)
                .delete(orgs::delete_org),
        )
        .route("/v1/orgs/{id}/members", get(orgs::list_members))
        .route(
            "/v1/orgs/{id}/members/{member_id}",
            patch(orgs::update_member).delete(orgs::remove_member),
        )
        .route(
            "/v1/orgs/{id}/invitations",
            get(orgs::list_invitations).post(orgs::create_invitation),
        )
        .route(
            "/v1/orgs/{id}/invitations/{inv_id}",
            delete(orgs::revoke_invitation),
        )
        .route(
            "/v1/orgs/{id}/invitations/{inv_id}/resends",
            post(orgs::resend_invitation),
        )
        // Authenticated invitation acceptance
        .route(
            "/v1/invitations/{id}/acceptances",
            post(invitations::accept_invitation),
        )
        .route_layer(axum_middleware::from_fn_with_state(state, require_auth));

    Router::new()
        .merge(public)
        .merge(authenticated)
        .merge(admin)
}
