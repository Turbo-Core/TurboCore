use actix_http::Request;
use actix_service::Service;
use actix_web::test;
use actix_web::{
	dev::ServiceResponse,
	web::{self, Data},
	App,
};
use api::{AppState, Argon2Config, Config, EmailConfig, JsonError};
use hmac::{Hmac, Mac};
use lettre::{AsyncSmtpTransport, Tokio1Executor};
use migration::{Migrator, MigratorTrait};
use std::path::Path;
use uaparser::UserAgentParser;

mod create_user;

pub async fn create_app(
	mailer: Option<AsyncSmtpTransport<Tokio1Executor>>,
	email: Option<EmailConfig>,
) -> impl Service<Request, Response = ServiceResponse, Error = actix_web::Error> {
	// Create a new HMAC-SHA256 key
	let secret_key = Hmac::new_from_slice("a_secret_key".repeat(3).as_bytes()).unwrap();

	// Load the regexes from the YAML file
	let ua_parser = UserAgentParser::from_yaml("../regexes.yaml").unwrap();

	// Create a connection to the database
	let connection;

	if !Path::new("../test.sqlite").exists() { // Prevent migration from running twice in tests
		connection = sea_orm::Database::connect("sqlite://../test.sqlite?mode=rwc".to_string())
			.await
			.unwrap();
		Migrator::up(&connection, None).await.unwrap();
	} else {
		connection = sea_orm::Database::connect("sqlite://../test.sqlite".to_string())
			.await
			.unwrap();
	}

	// Create the JSON config
	let json_cfg = web::JsonConfig::default().error_handler(|err, _req| {
		let err = format!("Error parsing JSON: {err}");
		log::warn!("{err}");
		JsonError {
			message: err,
			error_code: "JSON_ERROR".to_string(),
		}
		.into()
	});

	test::init_service(
		App::new()
			.app_data(Data::new(AppState {
				config: Config {
					bind_addr: "not_used".to_string(),
					connection_url: "sqlite://../test.sqlite?mode=rwc".to_string(),
					base_url: "http://turbocore".to_string(),
					secret_key,
					debug_level: "debug".to_string(),
					argon2_config: Argon2Config::default(),
					minimum_password_strength: 1,
					mailer,
					email,
				},
				connection,
				ua_parser,
			}))
			.app_data(json_cfg)
			.configure(api::auth::add_routes),
	)
	.await
}
