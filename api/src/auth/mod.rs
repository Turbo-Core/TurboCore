use actix_web::web;
use sea_orm::entity::prelude::DateTime;
use serde::Serialize;

pub mod change_password;
pub mod delete_user;
pub mod email_verify;
pub mod get_user;
pub mod login;
pub mod logout;
pub mod magic_link;
pub mod refresh;
pub mod reset_password;
pub mod create_user;
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

pub fn api_error(message: String, error_code: String) -> ApiResponse {
	ApiResponse::ApiError {
		message,
		error_code,
	}
}

pub fn add_routes(cfg: &mut web::ServiceConfig) {
	cfg.service(crate::auth::create_user::handler)
		.service(crate::auth::login::handler)
		.service(crate::auth::refresh::handler)
		.service(crate::auth::get_user::handler)
		.service(crate::auth::delete_user::handler)
		.service(crate::auth::change_password::handler)
		.service(crate::auth::email_verify::send_handler)
		.service(crate::auth::email_verify::receive_handler)
		.service(crate::auth::magic_link::get_handler)
		.service(crate::auth::magic_link::post_handler)
		.service(crate::auth::reset_password::handler);
}
