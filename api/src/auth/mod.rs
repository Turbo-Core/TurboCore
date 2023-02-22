use sea_orm::entity::prelude::DateTime;
use serde::Serialize;

pub mod change_password;
pub mod delete_user;
pub mod email_verify;
pub mod get_user;
pub mod login;
pub mod logout;
pub mod refresh;
pub mod reset_password;
pub mod signup;
pub mod update_user;
pub mod util;

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum ApiResponse {
    ApiError {
        message: String,
        error_code: String,
    },
    SignupResponse {
        uid: String,
    },
    LoginResponse {
        uid: String,
        token: String,
        expiry: i64,
        refresh_token: String,
        email_verified: bool,
        metadata: String,
    },
    RefreshResponse {
        uid: String,
        access_token: String,
        refresh_token: String,
        expiry: i64,
    },
    UserResponse {
        uid: String,
        email: String,
        created_at: DateTime,
        updated_at: DateTime,
        last_login: Option<DateTime>,
        active: bool,
        metadata: Option<String>,
        email_verified: bool,
    },
}
