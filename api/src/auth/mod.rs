use serde::Serialize;

pub mod login;
pub mod refresh;
pub mod signup;
pub mod util;

#[derive(Debug, Serialize)]
pub enum ApiResponse<'a> {
    ApiError {
        message: &'a str,
        error_code: &'a str,
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
}
