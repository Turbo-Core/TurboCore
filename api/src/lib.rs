pub mod auth;

#[derive(Debug, Clone)]
pub struct Config {
    pub connection_url: String,
    pub secret_key: hmac::Hmac<sha2::Sha256>,
    pub bcrypt_cost: u16,
    pub debug_level: String,
    pub bind_addr: String,
}

pub struct AppState {
    pub connection: sea_orm::DatabaseConnection,
    pub config: Config,
}