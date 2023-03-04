use lettre::AsyncSmtpTransport;
use lettre::Tokio1Executor;
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
