use actix_web::{
	http::{self, header::HeaderValue, StatusCode},
	web::Json,
};
use chrono::{Duration, NaiveDateTime, Utc};
use entity::refresh_tokens;
use hmac::Hmac;
use jwt::{SignWithKey, VerifyWithKey};
use rand::{distributions::Alphanumeric, thread_rng, Rng};
use sea_orm::{DatabaseConnection, EntityTrait, Set};
use sha2::Sha256;
use std::{collections::BTreeMap, str::FromStr};
use uuid::Uuid;

use super::ApiResponse;

/// Generates a JWT access token and a JWT refresh token, and expiry for the AT.
/// Returns the value as a tuple and store the refresh token in the database
pub async fn get_at_and_rt(
	connection: &DatabaseConnection,
	uid: &String,
	key: &hmac::Hmac<sha2::Sha256>,
) -> (String, String, i64) {
	let mut token = BTreeMap::new();
	let mut refresh_token = BTreeMap::new();

	// The RFC protocol allows for some lee way ("up to a few minutes") in exp, hence +15 seconds
	let short_exp = Utc::now().timestamp() + Duration::minutes(15).num_seconds() + 15;
	let short_exp_str = short_exp.to_string();
	let long_exp = Utc::now().timestamp() + Duration::days(30).num_seconds();
	let long_exp_str = long_exp.to_string();

	// RT is used as a primary key in db and must be unique. Two tokens (with same uid) generated in the same second will
	// be the same, so we add some randomness to make the possibility of a collision during the same second 1 / 62^5
	let rand_val: String = thread_rng()
		.sample_iter(&Alphanumeric)
		.take(5)
		.map(char::from)
		.collect();
	refresh_token.insert("iss", "TurboCore");
	refresh_token.insert("exp", &long_exp_str);
	refresh_token.insert("uid", uid);
	refresh_token.insert("type", "rt");
	refresh_token.insert("rand", &rand_val);

	token.insert("iss", "TurboCore");
	token.insert("exp", &short_exp_str);
	token.insert("type", "at");
	token.insert("uid", uid);

	let rt = refresh_token.sign_with_key(key).unwrap();

	// Add new one
	refresh_tokens::Entity::insert(refresh_tokens::ActiveModel {
		uid: Set(Uuid::from_str(uid).unwrap()),
		refresh_token: Set(rt.to_owned()),
		expiry: Set(NaiveDateTime::from_timestamp_opt(long_exp, 0).unwrap()),
		used: Set(false),
	})
	.exec(connection)
	.await
	.unwrap();

	(token.sign_with_key(key).unwrap(), rt, short_exp)
}

pub fn verify_header(auth_header: Option<&HeaderValue>, secret_key: &Hmac<Sha256>) -> HeaderResult {
	let authorization = match auth_header {
		Some(a) => {
			match a.to_str() {
				Ok(s) => s,
				Err(_e) => {
					// The request contains headers with opaque bytes.
					// TODO: Log IP address of the request
					log::warn!("Received a request that contains headers with opaque bytes. ");
					return HeaderResult::Error(
						Json(ApiResponse::ApiError {
							message: "The 'Authorization' header is improperly formatted"
								.to_string(),
							error_code: "BAD_HEADER".to_string(),
						}),
						http::StatusCode::BAD_REQUEST,
					);
				}
			}
		}
		None => {
			return HeaderResult::Error(
				Json(ApiResponse::ApiError {
					message: "The request is missing an 'Authorization' header".to_string(),
					error_code: "NOT_AUTHENTICATED".to_string(),
				}),
				http::StatusCode::UNAUTHORIZED,
			);
		}
	};

	let parts: Vec<&str> = authorization.split_whitespace().collect();
	if parts[0] != "Bearer" && parts[0] != "bearer" {
		return HeaderResult::Error(
			Json(ApiResponse::ApiError {
				message: "The 'Authorization' header is improperly formatted".to_string(),
				error_code: "BAD_HEADER".to_string(),
			}),
			http::StatusCode::BAD_REQUEST,
		);
	}
	let token = match parts.get(1) {
		Some(token) => *token,
		None => {
			return HeaderResult::Error(
				Json(ApiResponse::ApiError {
					message: "The 'Authorization' header is improperly formatted".to_string(),
					error_code: "BAD_HEADER".to_string(),
				}),
				http::StatusCode::BAD_REQUEST,
			);
		}
	};

	let claims: BTreeMap<String, String> = match token.verify_with_key(secret_key) {
		Ok(c) => c,
		Err(_) => {
			return HeaderResult::Error(
				Json(ApiResponse::ApiError {
					message: "The JWT could not be verified by the server".to_string(),
					error_code: "BAD_TOKEN".to_string(),
				}),
				http::StatusCode::UNAUTHORIZED,
			);
		}
	};

	if Utc::now().timestamp() > claims.get("exp").unwrap().parse().unwrap() {
		return HeaderResult::Error(
			Json(ApiResponse::ApiError {
				message: "The JWT has already expired".to_string(),
				error_code: "BAD_TOKEN".to_string(),
			}),
			http::StatusCode::UNAUTHORIZED,
		);
	}

	if claims.get("type").unwrap() != "at" {
		return HeaderResult::Error(
			Json(ApiResponse::ApiError {
				message: "The JWT is not an access token".to_string(),
				error_code: "BAD_TOKEN".to_string(),
			}),
			http::StatusCode::UNAUTHORIZED,
		);
	}

	let uid = &claims.get("uid").unwrap()[..];

	HeaderResult::Uid(Uuid::from_str(uid).unwrap())
}

pub enum HeaderResult {
	Error(Json<ApiResponse>, StatusCode),
	Uid(Uuid),
}

#[cfg(test)]
mod tests {
	use super::*;
	use actix_web::http::header;
	use entity::refresh_tokens;
	use hmac::{Hmac, Mac};
	use migration::TableCreateStatement;
	use sea_orm::{ConnectionTrait, DbBackend, Schema};

	#[actix_web::test]
	async fn test_get_at_and_rt() {
		let uid = "6755d7b1-38f2-4a3a-b872-98d0e7bbd1ee";

		// Create a connection to a test database
		let connection = sea_orm::Database::connect("sqlite::memory:").await.unwrap();

		// Create the schema
		let schema = Schema::new(DbBackend::Sqlite);
		let stmt: TableCreateStatement = schema.create_table_from_entity(refresh_tokens::Entity);

		let _result = connection
			.execute(connection.get_database_backend().build(&stmt))
			.await
			.unwrap();

		// Create Hmac key
		let key: Hmac<sha2::Sha256> = Hmac::new_from_slice(b"a_very_long_secret_key").unwrap();

		// Create a new at and rt pair
		let (at, rt, exp) = get_at_and_rt(&connection, &uid.to_string(), &key).await;

		// Verify the at
		let claims: BTreeMap<String, String> = at.verify_with_key(&key).unwrap();
		assert_eq!(claims["type"], "at");
		assert_eq!(claims["uid"], uid);
		assert_eq!(claims["exp"], exp.to_string());
		assert!(claims["exp"].parse::<i64>().unwrap() - Utc::now().timestamp() > 905); // 915 is the default expiry time
		assert!(claims["exp"].parse::<i64>().unwrap() - Utc::now().timestamp() < 925);
		assert_eq!(claims["iss"], "TurboCore");

		// Verify the rt
		let claims: BTreeMap<String, String> = rt.verify_with_key(&key).unwrap();
		assert_eq!(claims["type"], "rt");
		assert_eq!(claims["uid"], uid);
		assert!(claims["exp"].parse::<i64>().unwrap() - Utc::now().timestamp() > 2591990); // 2592000 is the default expiry time
		assert!(claims["exp"].parse::<i64>().unwrap() - Utc::now().timestamp() < 2592010);
		assert!(claims["rand"].len() > 0);
		assert_eq!(claims["iss"], "TurboCore");

		// Verify that the rt is in the database
		let rt = refresh_tokens::Entity::find_by_id(rt)
			.one(&connection)
			.await
			.unwrap()
			.unwrap();
		assert_eq!(rt.uid, Uuid::from_str(uid).unwrap());

		// Close the connection
		connection.close().await.unwrap();
	}

	#[test]
	fn test_good_header() {
		let uid = "6755d7b1-38f2-4a3a-b872-98d0e7bbd1ee";

		// Create Hmac key
		let key: Hmac<sha2::Sha256> = Hmac::new_from_slice(b"a_very_long_secret_key").unwrap();

		// Create a good at
		let mut claims: BTreeMap<&str, &str> = BTreeMap::new();
		claims.insert("iss", "TurboCore");
		claims.insert("type", "at");
		claims.insert("uid", uid);
		claims.insert("exp", "9999999999");
		let at = claims.sign_with_key(&key).unwrap();

		// Create the request and pull the headers
		let request = actix_web::test::TestRequest::default()
			.insert_header((header::AUTHORIZATION, format!("Bearer {}", at)))
			.to_http_request();
		let header_map = request.headers();

		// Test the header
		let res = verify_header(header_map.get("authorization"), &key);

		match res {
			HeaderResult::Uid(u) => assert_eq!(u, Uuid::from_str(uid).unwrap()),
			_ => assert!(false),
		}
	}

	#[test]
	fn test_bad_header() {
		let uid = "6755d7b1-38f2-4a3a-b872-98d0e7bbd1ee";

		// Create a good Hmac key
		let key1: Hmac<sha2::Sha256> = Hmac::new_from_slice(b"a_very_long_secret_key").unwrap();

		// and a bad one
		let key2: Hmac<sha2::Sha256> = Hmac::new_from_slice(b"incorrect_secret_key").unwrap();

		// Create a good at
		let mut claims: BTreeMap<&str, &str> = BTreeMap::new();
		claims.insert("iss", "TurboCore");
		claims.insert("type", "at");
		claims.insert("uid", uid);
		claims.insert("exp", "9999999999");
		let at = claims.sign_with_key(&key1).unwrap();

		// Create the request and pull the headers
		let request = actix_web::test::TestRequest::default()
			.insert_header((header::AUTHORIZATION, format!("Bearer {}", at)))
			.to_http_request();
		let header_map = request.headers();

		// Test the header
		let res = verify_header(header_map.get("authorization"), &key2);

		match res {
			HeaderResult::Error(json, code) => {
				assert_eq!(code, http::StatusCode::UNAUTHORIZED);
				let json = json.into_inner();
				match json {
					ApiResponse::ApiError {
						message: _,
						error_code,
					} => {
						assert_eq!(error_code, "BAD_TOKEN");
					}
					_ => assert!(false),
				}
			}
			_ => assert!(false),
		}
	}

	#[test]
	fn test_no_header() {
		// Create a key
		let key: Hmac<sha2::Sha256> = Hmac::new_from_slice(b"not_used").unwrap();

		// Test no header
		let res = verify_header(None, &key);
		match res {
			HeaderResult::Error(json, code) => {
				assert_eq!(code, http::StatusCode::UNAUTHORIZED);
				let json = json.into_inner();
				match json {
					ApiResponse::ApiError {
						message: _,
						error_code,
					} => {
						assert_eq!(error_code, "NOT_AUTHENTICATED");
					}
					_ => assert!(false),
				}
			}
			_ => assert!(false),
		}
	}

	#[test]
	fn test_bad_formatting() {
		let uid = "6755d7b1-38f2-4a3a-b872-98d0e7bbd1ee";

		// Create Hmac key
		let key: Hmac<sha2::Sha256> = Hmac::new_from_slice(b"a_very_long_secret_key").unwrap();

		// Create a good at
		let mut claims: BTreeMap<&str, &str> = BTreeMap::new();
		claims.insert("iss", "TurboCore");
		claims.insert("type", "at");
		claims.insert("uid", uid);
		claims.insert("exp", "9999999999");
		let at = claims.sign_with_key(&key).unwrap();

		// Create the request and pull the headers
		let request = actix_web::test::TestRequest::default()
			.insert_header((header::AUTHORIZATION, format!("Beerer {}", at))) // Misspelled Bearer
			.to_http_request();
		let header_map = request.headers();

		// Test the header
		let res = verify_header(header_map.get("authorization"), &key);

		match res {
			HeaderResult::Error(json, code) => {
				assert_eq!(code, http::StatusCode::BAD_REQUEST);
				let json = json.into_inner();
				match json {
					ApiResponse::ApiError {
						message: _,
						error_code,
					} => {
						assert_eq!(error_code, "BAD_HEADER");
					}
					_ => assert!(false),
				}
			}
			_ => assert!(false),
		}
	}

	#[test]
	pub fn test_not_bearer() {
		let uid = "6755d7b1-38f2-4a3a-b872-98d0e7bbd1ee";

		// Create Hmac key
		let key: Hmac<sha2::Sha256> = Hmac::new_from_slice(b"a_very_long_secret_key").unwrap();

		// Create a good at
		let mut claims: BTreeMap<&str, &str> = BTreeMap::new();
		claims.insert("iss", "TurboCore");
		claims.insert("type", "at");
		claims.insert("uid", uid);
		claims.insert("exp", "9999999999");
		let at = claims.sign_with_key(&key).unwrap();

		// Create the request and pull the headers
		let request = actix_web::test::TestRequest::default()
			.insert_header((header::AUTHORIZATION, at)) // Just the token with no Bearer
			.to_http_request();
		let header_map = request.headers();

		// Test the header
		let res = verify_header(header_map.get("authorization"), &key);

		match res {
			HeaderResult::Error(json, code) => {
				assert_eq!(code, http::StatusCode::BAD_REQUEST);
				let json = json.into_inner();
				match json {
					ApiResponse::ApiError {
						message: _,
						error_code,
					} => {
						assert_eq!(error_code, "BAD_HEADER");
					}
					_ => assert!(false),
				}
			}
			_ => assert!(false),
		}
	}

	#[test]
	pub fn expired_token() {
		let uid = "6755d7b1-38f2-4a3a-b872-98d0e7bbd1ee";

		// Create Hmac key
		let key: Hmac<sha2::Sha256> = Hmac::new_from_slice(b"a_very_long_secret_key").unwrap();

		// Get the current time
		let now = Utc::now().timestamp() - 16; // 16 seconds ago
		let now = now.to_string();

		// Create a good at
		let mut claims: BTreeMap<&str, &str> = BTreeMap::new();
		claims.insert("iss", "TurboCore");
		claims.insert("type", "at");
		claims.insert("uid", uid);
		claims.insert("exp", &now);
		let at = claims.sign_with_key(&key).unwrap();

		// Create the request and pull the headers
		let request = actix_web::test::TestRequest::default()
			.insert_header((header::AUTHORIZATION, format!("Bearer {}", at)))
			.to_http_request();
		let header_map = request.headers();

		// Test the header
		let res = verify_header(header_map.get("authorization"), &key);

		match res {
			HeaderResult::Uid(u) => assert_eq!(u, Uuid::from_str(uid).unwrap()),
			_ => assert!(false),
		}
	}
}
