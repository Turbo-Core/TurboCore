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
	pub connection_url: String,
	pub secret_key: hmac::Hmac<sha2::Sha256>,
	pub bcrypt_cost: u32,
	pub debug_level: String,
	pub bind_addr: String,
	pub argon2_config: Argon2Config,
	pub minimum_password_strength: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Argon2Config {
	pub salt_length: u32,
	pub memory: u32,
	pub iterations: u32,
	pub parallelism: u32,
	pub tag_length: u32,
}

pub struct AppState {
	pub connection: sea_orm::DatabaseConnection,
	pub config: Config,
}
