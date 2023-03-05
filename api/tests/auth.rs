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

	use std::{collections::BTreeMap, str::FromStr};

	use actix_web::http::header::ContentType;
	use jwt::VerifyWithKey;

	use super::*;

	// ****************************************************
	// *                                                  *
	// *                    user/create                   *
	// *                                                  *
	// ****************************************************
	#[actix_web::test]
	async fn test_create_user_pure() {
		#[derive(serde::Deserialize, Debug)]
		struct ExpectedResponse {
			uid: String,
		}

		let app = create_app().await;
		let req = test::TestRequest::post().uri("/api/auth/user/create")
			.insert_header(ContentType::json())
			.set_payload(r##"{"email":"test@example.com","password":"a_strong_password1111011","login":false,"email_verified":false,"metadata":""}"##).to_request();
		let resp: ExpectedResponse = test::call_and_read_body_json(&app, req).await;
		Uuid::from_str(&resp.uid).unwrap();
	}

	#[actix_web::test]
	async fn test_create_user_weak_password() {
		#[derive(serde::Deserialize, Debug)]
		struct ExpectedResponse {
			message: String,
			error_code: String,
		}

		let app = create_app().await;
		let req = test::TestRequest::post().uri("/api/auth/user/create")
			.insert_header(ContentType::json())
			.set_payload(r##"{"email":"test1@example.com","password":"password","login":false,"email_verified":false,"metadata":""}"##).to_request();
		// Notice that the password is too weak
		let resp: ExpectedResponse = test::call_and_read_body_json(&app, req).await;
		assert_eq!(resp.error_code, "INVALID_PASSWORD");
		assert!(resp.message.contains("too weak"));
	}

	#[actix_web::test]
	async fn test_create_user_invalid_email() {
		#[derive(serde::Deserialize, Debug)]
		struct ExpectedResponse {
			message: String,
			error_code: String,
		}

		let app = create_app().await;
		let req = test::TestRequest::post().uri("/api/auth/user/create")
			.insert_header(ContentType::json())
			.set_payload(r##"{"email":"test@example.","password":"password","login":false,"email_verified":false,"metadata":""}"##).to_request();
		// The email is missing the TLD
		let resp: ExpectedResponse = test::call_and_read_body_json(&app, req).await;
		assert_eq!(resp.error_code, "INVALID_EMAIL");
		assert!(resp.message.contains("invalid") && resp.message.contains("email"));
	}

	#[actix_web::test]
	async fn test_create_user_email_exists() {
		#[derive(serde::Deserialize, Debug)]
		struct ExpectedResponse1 {
			uid: String,
		}

		#[derive(serde::Deserialize, Debug)]
		struct ExpectedResponse2 {
			message: String,
			error_code: String,
		}

		let app = create_app().await;
		let req1 = test::TestRequest::post().uri("/api/auth/user/create")
			.insert_header(ContentType::json())
			.set_payload(r##"{"email":"exists@example.com","password":"a_strong_password1111011","login":false,"email_verified":false,"metadata":""}"##).to_request();

		// Create the user
		let resp: ExpectedResponse1 = test::call_and_read_body_json(&app, req1).await;
		let _uid = Uuid::from_str(&resp.uid).unwrap(); // Valid UUID

		let req2 = test::TestRequest::post().uri("/api/auth/user/create")
			.insert_header(ContentType::json())
			.set_payload(r##"{"email":"exists@example.com","password":"a_strong_password1111011","login":false,"email_verified":false,"metadata":""}"##).to_request();

		// Try to create the user again
		let resp: ExpectedResponse2 = test::call_and_read_body_json(&app, req2).await;
		assert_eq!(resp.error_code, "EMAIL_ALREADY_IN_USE");
		assert!(resp.message.contains("in use"));
	}

	#[actix_web::test]
	async fn test_create_user_sign_in() {
		#[derive(serde::Deserialize, Debug)]
		struct ExpectedResponse {
			uid: String,
			token: String,
			expiry: u64,
			refresh_token: String,
			email_verified: bool,
			metadata: String,
		}

		let app = create_app().await;
		let req = test::TestRequest::post().uri("/api/auth/user/create")
			.insert_header(ContentType::json())
			.set_payload(r##"{"email":"login@example.com","password":"a_strong_password1111011","login":true,"email_verified":false,"metadata":""}"##).to_request();
		let resp: ExpectedResponse = test::call_and_read_body_json(&app, req).await;
		Uuid::from_str(&resp.uid).unwrap(); // Valid UUID

		// Confirm that email_verified is false
		assert_eq!(resp.email_verified, false);

		// Confirm that the metadata is empty
		assert_eq!(resp.metadata, "");

		// Confirm that the tokens are valid
		let secret_key: Hmac<sha2::Sha256> =
			Hmac::new_from_slice("a_secret_key".repeat(3).as_bytes()).unwrap();
		let claims: BTreeMap<String, String> = resp.token.verify_with_key(&secret_key).unwrap();
		assert_eq!(claims["iss"], "TurboCore");
		assert_eq!(claims["uid"], resp.uid);
		assert_eq!(claims["type"], "at");
		assert_eq!(claims["exp"].parse::<u64>().unwrap(), resp.expiry);

		let claims: BTreeMap<String, String> =
			resp.refresh_token.verify_with_key(&secret_key).unwrap();
		assert_eq!(claims["iss"], "TurboCore");
		assert_eq!(claims["uid"], resp.uid);
		assert_eq!(claims["type"], "rt");
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
					minimum_password_strength: 1,
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
