use serde::{Serialize, Deserialize};

pub mod auth;

#[derive(Debug, Clone)]
pub struct Config {
    pub connection_url: String,
    pub secret_key: hmac::Hmac<sha2::Sha256>,
    pub bcrypt_cost: u32,
    pub debug_level: String,
    pub bind_addr: String,
    pub argon2_config: Argon2Config
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Argon2Config {
    pub salt_length: u32,
    pub memory: u32,
    pub iterations: u32,
    pub parallelism: u32,
    pub tag_length: u32
}

pub struct AppState {
    pub connection: sea_orm::DatabaseConnection,
    pub config: Config,
}