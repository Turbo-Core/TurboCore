use core::panic;
use std::num::NonZeroUsize;

use actix_http::{body::BoxBody, StatusCode};
use actix_web::{http::header, web::BytesMut, HttpResponse, ResponseError};
use lettre::{AsyncSmtpTransport, Tokio1Executor};
use regex::Regex;
use serde::{Deserialize, Serialize};

pub mod auth;

#[macro_use]
extern crate lazy_static;

// Using lazy static to avoid compiling this regex every time we need it, as the computation is expensive
lazy_static! {
	pub static ref EMAIL_REGEX: Regex = Regex::new(r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$").unwrap();
}

#[derive(Debug, Clone)]
pub struct Config {
	pub base_url: String,
	pub connection_url: String,
	pub secret_key: hmac::Hmac<sha2::Sha256>,
	pub debug_level: String,
	pub bind_addr: String,
	pub argon2_config: Argon2Config,
	pub minimum_password_strength: u8,
	pub mailer: Option<AsyncSmtpTransport<Tokio1Executor>>,
	pub email: Option<EmailConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Argon2Config {
	pub salt_length: u32,
	pub memory: u32,
	pub iterations: u32,
	pub parallelism: u32,
	pub tag_length: u32,
}

impl Default for Argon2Config {
	fn default() -> Self {
		Self {
			salt_length: 16,
			memory: 65536,
			iterations: 4,
			parallelism: match std::thread::available_parallelism() {
				Ok(num) => {
					(num.get() as f64 / 2.0).ceil() as u32
				},
				Err(_) => 1,
			},
			tag_length: 32,
		}
	}
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailConfig {
	pub smtp_server: String,
	pub smtp_port: u16,
	pub smtp_username: String,
	pub smtp_password: String,
	pub smtp_encryption: String,
	pub from: String,
	pub reply_to: String,
	pub magic_link_subject: String,
	pub forgot_password_subject: String,
	pub confirmation_subject: String,
}

pub struct AppState {
	pub connection: sea_orm::DatabaseConnection,
	pub config: Config,
	pub ua_parser: uaparser::UserAgentParser,
}

#[derive(Debug)]
pub struct JsonError {
	pub message: String,
	pub error_code: String,
}

impl std::fmt::Display for JsonError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("JsonError")
			.field("message", &self.message)
			.field("error_code", &self.error_code)
			.finish()
	}
}

impl ResponseError for JsonError {
	fn status_code(&self) -> StatusCode {
		StatusCode::BAD_REQUEST
	}

	fn error_response(&self) -> HttpResponse<BoxBody> {
		let mut res = HttpResponse::new(self.status_code());

		res.headers_mut()
			.insert(header::CONTENT_TYPE, header::HeaderValue::from_static("application/json"));

		let box_body = BoxBody::new(BytesMut::from(
			format!(
				"{{\"message\": \"{}\", \"error_code\": \"{}\"}}",
				self.message, self.error_code
			)
			.as_bytes(),
		));

		res.set_body(box_body)
	}
}
