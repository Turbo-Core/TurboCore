use api::{Argon2Config, Config, EmailConfig};
use hmac::{Hmac, Mac};
use lettre::transport::smtp::authentication::Credentials;
use lettre::transport::smtp::client::{Tls, TlsParameters};
use lettre::{AsyncSmtpTransport, Tokio1Executor};
use serde::{Deserialize, Serialize};
use std::fs;
use uuid::Uuid;

/// The config struct represents data located in the config.json file.
/// It's loaded every time the app starts
#[derive(Serialize, Deserialize)]
pub struct ConfigInternal {
	pub base_url: String,
	pub connection_url: String,
	pub secret_key: Option<String>,
	pub bcrypt_cost: Option<u32>,
	pub debug_level: Option<String>,
	pub bind_addr: Option<String>,
	pub argon2_params: Option<Argon2Config>,
	pub email: Option<EmailConfig>,
	pub minimum_password_strength: Option<u8>,
}

fn verify_connection_url(url: &str) -> bool {
	let url = url.to_lowercase();
	url.starts_with("mysql:") || url.starts_with("postgres:") || url.starts_with("sqlite:")
}

/// Loads the contents of config.json and returns it as a Config object
/// Panics if the contents are invalid JSON or if a key-value pair is not supported.
pub fn load_config() -> Config {
	let config_str = fs::read_to_string("./config.json").expect("Cannot read config file, config.json. Check that the file exists and has correct permissions.");
	let json_config: ConfigInternal =
		serde_json::from_str(&config_str).expect("Failed to parse config file.");

	let config = Config {
		base_url: json_config.base_url,
		connection_url: json_config.connection_url,
		secret_key: match json_config.secret_key {
			Some(key) => Hmac::new_from_slice(key.as_bytes()).unwrap(),
			None => Hmac::new_from_slice(Uuid::new_v4().as_bytes()).unwrap(),
		},
		bcrypt_cost: json_config.bcrypt_cost.unwrap_or(12),
		debug_level: match json_config.debug_level {
			Some(level) => {
				if level.eq_ignore_ascii_case("debug")
					|| level.eq_ignore_ascii_case("info")
					|| level.eq_ignore_ascii_case("error")
				{
					level
				} else {
					panic!("Unsupported debug level: {level}")
				}
			}
			None => "info".to_string(),
		},
		bind_addr: match json_config.bind_addr {
			Some(addr) => addr,
			None => "127.0.0.1:8080".to_string(),
		},
		argon2_config: match json_config.argon2_params {
			Some(c) => c,
			None => Argon2Config {
				salt_length: 16,
				memory: 65536,
				iterations: 4,
				parallelism: std::thread::available_parallelism().unwrap().get() as u32 / 2,
				tag_length: 32,
			},
		},
		minimum_password_strength: json_config.minimum_password_strength.unwrap_or(1),
		mailer: match json_config.email {
			Some(ref email_config) => {
				let mut mailer =
					AsyncSmtpTransport::<Tokio1Executor>::relay(&email_config.smtp_server)
						.unwrap()
						.port(email_config.smtp_port);
				let tls = match email_config.smtp_encryption.as_str() {
					"None" | "none" => Tls::None,
					"TLS" | "tls" => Tls::Required(
						TlsParameters::new_native(email_config.smtp_server.clone()).unwrap(),
					),
					"STARTTLS" | "starttls" => Tls::Opportunistic(
						TlsParameters::new_native(email_config.smtp_server.clone()).unwrap(),
					),
					_ => {
						panic!("Provided TLS method is not supported")
					}
				};
				if !"".eq(&email_config.smtp_username) {
					mailer = mailer.credentials(Credentials::new(
						email_config.smtp_username.clone(),
						email_config.smtp_password.clone(),
					));
				}
				Some(mailer.tls(tls).build())
			}
			None => None,
		},
		email: json_config.email,
	};

	if !verify_connection_url(&config.connection_url) {
		panic!("Unsupported connection URL: {}", config.connection_url)
	}
	if config.argon2_config.salt_length < 8 {
		panic!("Salt length too short. Must be at least 8")
	}
	config
}
