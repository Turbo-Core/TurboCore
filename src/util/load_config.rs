use std::{fs, path::Path};
use serde::{Serialize, Deserialize};

/// The config struct represents data located in the config.json file. 
/// It's loaded every time the app starts
#[derive(Serialize, Deserialize)]
pub struct Config {
    pub database: String,
    pub debug_level: String
}

/// Loads the contents of config.json and returns it as a Config object
/// Panics if the contents are invalid JSON or if a key-value pair is not supported.
pub fn load_config() -> Config {
    let config_path = Path::new("./config.json");

    let config_str = fs::read_to_string(config_path).expect("Cannot read config file, config.json. Check that the file exists and has correct permissions.");
    let config: Config = serde_json::from_str(&config_str).expect("Failed to parse config file.");

    if !(config.database.eq_ignore_ascii_case("postgres") || config.database.eq_ignore_ascii_case("mongodb")) {
        panic!("Unsupported database type: {}", config.database);
    }

    if !(config.debug_level.eq_ignore_ascii_case("debug")
        || config.debug_level.eq_ignore_ascii_case("info")
        || config.debug_level.eq_ignore_ascii_case("error")) {
            panic!("Unsupported debug level: {}", config.debug_level)
    }
    config
}