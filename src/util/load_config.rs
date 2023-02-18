use api::{Config, Argon2Config};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use std::fs;
use uuid::Uuid;

/// The config struct represents data located in the config.json file.
/// It's loaded every time the app starts
#[derive(Serialize, Deserialize)]
pub struct ConfigInternal {
    pub connection_url: String,
    pub secret_key: Option<String>,
    pub bcrypt_cost: Option<u32>,
    pub debug_level: Option<String>,
    pub bind_addr: Option<String>,
    pub argon2_params: Option<Argon2Config>
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
                parallelism: std::thread::available_parallelism().unwrap().get() as u32/2,
                tag_length: 32
            }
        }
    };

    if !verify_connection_url(&config.connection_url) {
        panic!("Unsupported connection URL: {}", config.connection_url)
    }
    if config.argon2_config.salt_length < 8 {
        panic!("Salt length too short. Must be at least 8")
    }
    config
}
