use crate::auth::create_app;
use actix_web::test;
use hmac::{Hmac, Mac};
use uuid::Uuid;

mod tests {
	use std::{collections::BTreeMap, str::FromStr};

	use actix_web::http::header::ContentType;
	use jwt::VerifyWithKey;

	use super::*;

	#[actix_web::test]
	async fn test_create_user_pure() {
		#[derive(serde::Deserialize, Debug)]
		struct ExpectedResponse {
			uid: String,
		}

		let app = create_app(None, None).await;
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

		let app = create_app(None, None).await;
		let req = test::TestRequest::post().uri("/api/auth/user/create")
			.insert_header(ContentType::json())
			.set_payload(r##"{"email":"test1@example.com","password":"password","login":false,"email_verified":false,"metadata":""}"##).to_request();
		// Notice that the password is too weak
		let resp: ExpectedResponse = test::call_and_read_body_json(&app, req).await;
		assert_eq!(resp.error_code, "WEAK_PASSWORD");
		assert!(resp.message.contains("too weak"));
	}

	#[actix_web::test]
	async fn test_create_user_invalid_email() {
		#[derive(serde::Deserialize, Debug)]
		struct ExpectedResponse {
			message: String,
			error_code: String,
		}

		let app = create_app(None, None).await;
		let req = test::TestRequest::post().uri("/api/auth/user/create")
			.insert_header(ContentType::json())
			.set_payload(r##"{"email":"test@example.","password":"password","login":false,"email_verified":false,"metadata":""}"##).to_request();
		// The email is missing the TLD
		let resp: ExpectedResponse = test::call_and_read_body_json(&app, req).await;
		assert_eq!(resp.error_code, "EMAIL_IN_USE");
		assert!(resp.message.contains("in use") && resp.message.contains("email"));
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

		let app = create_app(None, None).await;
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
		assert_eq!(resp.error_code, "EMAIL_IN_USE");
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

		let app = create_app(None, None).await;
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
