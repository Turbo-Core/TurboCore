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

	// TODO: make exp configurable
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
					// TODO: Log this
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
