use actix_http::Request;
use actix_web::{
	dev::ServiceResponse,
	test,
	web::{self, Data},
	App,
};
use api::{auth, AppState, Argon2Config, Config, JsonError};
use hmac::{Hmac, Mac};
use migration::{Migrator, MigratorTrait};
use uaparser::UserAgentParser;
use uuid::Uuid;

mod tests {

	use std::str::FromStr;

	use actix_web::http::header::ContentType;

	use super::*;

	#[actix_web::test]
	async fn test_create_user_pure() {
		#[derive(serde::Deserialize, Debug)]
		struct ExpectedResponse {
			uid: String,
		}

		let app = create_app().await;
		let req = test::TestRequest::post().uri("/api/auth/user/create")
			.insert_header(ContentType::json())
			.set_payload(r##"{"email":"test@example.com","password":"test1234","login":false,"email_verified":false,"metadata":""}"##).to_request();
		let resp: ExpectedResponse = test::call_and_read_body_json(&app, req).await;
		Uuid::from_str(&resp.uid).unwrap();
	}
}

async fn create_app(
) -> impl actix_service::Service<Request, Response = ServiceResponse, Error = actix_web::Error> {
	// Create a new HMAC-SHA256 key
	let secret_key = Hmac::new_from_slice("a_secret_key".repeat(3).as_bytes()).unwrap();

	// Load the regexes from the YAML file
	let ua_parser = UserAgentParser::from_yaml("../regexes.yaml").unwrap();

	// Create a connection to the database
	let connection = sea_orm::Database::connect("sqlite://../test.sqlite?mode=rwc".to_string())
		.await
		.unwrap();

	// Run the migrations
	Migrator::up(&connection, None).await.unwrap();

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
					minimum_password_strength: 0,
					mailer: None,
					email: None,
				},
				connection,
				ua_parser,
			}))
			.app_data(json_cfg)
			.configure(add_routes),
	)
	.await
}

fn add_routes(cfg: &mut web::ServiceConfig) {
	cfg.service(auth::signup::handler)
		.service(auth::login::handler)
		.service(auth::refresh::handler)
		.service(auth::get_user::handler)
		.service(auth::delete_user::handler)
		.service(auth::change_password::handler)
		.service(auth::email_verify::send_handler)
		.service(auth::email_verify::receive_handler)
		.service(auth::magic_link::get_handler)
		.service(auth::magic_link::post_handler)
		.service(auth::reset_password::handler);
}
