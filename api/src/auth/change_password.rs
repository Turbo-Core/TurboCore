extern crate zxcvbn;

use std::collections::BTreeMap;

use crate::auth::util;
use crate::{auth::ApiResponse, AppState};
use actix_web::{
	http, patch,
	web::{Data, Json},
	Either, HttpResponse,
};
use argon2::{Config as ArgonConfig, ThreadMode, Variant, Version};
use chrono::Utc;
use entity::{password_reset_tokens, users};
use jwt::VerifyWithKey;
use log::error;
use rand::{thread_rng, Rng};
use sea_orm::{ActiveModelTrait, EntityTrait, Set, ModelTrait};
use serde::Deserialize;
use zxcvbn::zxcvbn;

use super::util::HeaderResult;

#[derive(Deserialize)]
pub struct ChangePassBody {
	old_password: String,
	new_password: String,
}

#[patch("/api/auth/user/change-password")]
pub async fn handler(
	request: actix_web::HttpRequest,
	data: Data<AppState>,
	body: Json<ChangePassBody>,
) -> ChangePassResponse<'static> {
	let header_map = request.headers();
	let authorization = header_map.get("Authorization");

	let uid = match util::verify_header(authorization, &data.config.secret_key) {
		HeaderResult::Error(r, s) => {
			return Either::Left((r, s));
		}
		HeaderResult::Uid(uid) => uid,
	};

	// Check if the new password strength is acceptable.
	// This is done first as it has a much lower cost than database queries
	let estimate = match zxcvbn(&body.new_password, &[]) {
		Ok(ent) => ent,
		Err(_) => {
			return Either::Left((
				Json(ApiResponse::ApiError {
					message: "An empty password was provided.".to_string(),
					error_code: "INVALID_PASSWORD".to_string(),
				}),
				http::StatusCode::BAD_REQUEST,
			));
		}
	};
	let score = estimate.score();
	if score < data.config.minimum_password_strength {
		let feedback_msg = match estimate.feedback().clone() {
			Some(w) => match w.warning() {
				Some(w) => format!("The password provided is too weak. {w}",),
				None => "The password provided is too weak.".to_string(),
			},
			None => "The password provided is too weak.".to_string(),
		};
		return Either::Left((
			Json(ApiResponse::ApiError {
				message: feedback_msg,
				error_code: "INVALID_PASSWORD".to_string(),
			}),
			http::StatusCode::BAD_REQUEST,
		));
	}
	
	// This variable will be used to store the password reset token model if the old password is a reset token
	let mut reset_token_model: Option<password_reset_tokens::Model> = None;

	// Check if old_password is a reset token
	let claims = match body.old_password.verify_with_key(&data.config.secret_key) {
		Ok::<BTreeMap<String, String>, _>(claims) => Some(claims),
		Err(_) => {
			None // Not a reset token
		}
	};
	if let Some(claims) = claims {
		// Check if the token is expired
		if Utc::now().timestamp() > claims["exp"].parse().unwrap() {
			return Either::Left((
				Json(ApiResponse::ApiError {
					message: "The password reset token has already expired.".to_string(),
					error_code: "INVALID_TOKEN".to_string(),
				}),
				http::StatusCode::BAD_REQUEST,
			));
		}

		if claims["type"] != "password_reset" {
			return Either::Left((
				Json(ApiResponse::ApiError {
					message: "The password reset token provided is invalid.".to_string(),
					error_code: "INVALID_TOKEN".to_string(),
				}),
				http::StatusCode::BAD_REQUEST,
			));
		}
		
		match password_reset_tokens::Entity::find_by_id(&claims["token"])
			.one(&data.connection)
			.await
		{
			Ok(model) => {
				if model.is_none() {
					return Either::Left((
						Json(ApiResponse::ApiError {
							message: "The password reset token provided is invalid.".to_string(),
							error_code: "INVALID_TOKEN".to_string(),
						}),
						http::StatusCode::BAD_REQUEST,
					));
				}
				// If the token is valid, we'll store the model in the reset_token_model variable to be deleted later
				reset_token_model = Some(model.unwrap());
			}
			Err(e) => {
				error!("Error while finding password reset token: {}", e);
				return Either::Left((
					Json(ApiResponse::ApiError {
						message: "An error occurred while processing your request.".to_string(),
						error_code: "INTERNAL_SERVER_ERROR".to_string(),
					}),
					http::StatusCode::INTERNAL_SERVER_ERROR,
				));
			}
		}
	}

	// If the new password strength is good, we wil find the user and verify their password if they're not using a reset token
	let user = match users::Entity::find_by_id(uid).one(&data.connection).await {
		Ok(user_model) => match user_model {
			Some(user_model) => user_model,
			None => {
				return Either::Left((
					Json(ApiResponse::ApiError {
						message: "The user was not found.".to_string(),
						error_code: "USER_NOT_FOUND".to_string(),
					}),
					http::StatusCode::NOT_FOUND,
				));
			}
		},
		Err(e) => {
			error!("An error occurred when finding user. Error: {}", e.to_string());
			return Either::Left((
				Json(ApiResponse::ApiError {
					message: "Internal server error.".to_string(),
					error_code: "INTERNAL_SERVER_ERROR".to_string(),
				}),
				http::StatusCode::INTERNAL_SERVER_ERROR,
			));
		}
	};

	// If the old password is not a reset token, then we'll verify it
	if reset_token_model.is_none() && !argon2::verify_encoded(&user.password, body.old_password.as_bytes()).unwrap() {
		return Either::Left((
			Json(ApiResponse::ApiError {
				message: "The email or password is invalid".to_string(),
				error_code: "INVALID_CREDENTIALS".to_string(),
			}),
			http::StatusCode::UNAUTHORIZED,
		));
	}

	// Hash and store the new password
	let config = ArgonConfig {
		variant: Variant::Argon2id,
		version: Version::Version13,
		mem_cost: data.config.argon2_config.memory,
		time_cost: data.config.argon2_config.iterations,
		lanes: data.config.argon2_config.parallelism,
		thread_mode: ThreadMode::Parallel,
		secret: &[],
		ad: &[],
		hash_length: data.config.argon2_config.tag_length,
	};

	let salt: Vec<u8> = (0..data.config.argon2_config.salt_length)
		.map(|_| thread_rng().gen_range(0..255))
		.collect();

	let password_hash =
		argon2::hash_encoded(body.new_password.as_bytes(), salt.as_slice(), &config).unwrap();

	let mut user: users::ActiveModel = user.into();
	user.password = Set(password_hash);
	match user.update(&data.connection).await {
		Ok(_) => (),
		Err(e) => {
			error!("Failed to change user password. Error: {}", e.to_string());
			return Either::Left((
				Json(ApiResponse::ApiError {
					message: "Failed to change the password.".to_string(),
					error_code: "INTERNAL_SERVER_ERROR".to_string(),
				}),
				http::StatusCode::INTERNAL_SERVER_ERROR,
			));
		}
	}

	// If the old password was a reset token, we'll delete it
	if let Some(token) = reset_token_model {
		match token.delete(&data.connection).await {
			Ok(_) => (),
			Err(e) => {
				error!("Failed to delete password reset token. Error: {}", e.to_string());
				return Either::Left((
					Json(ApiResponse::ApiError {
						message: "Failed to change the password.".to_string(),
						error_code: "INTERNAL_SERVER_ERROR".to_string(),
					}),
					http::StatusCode::INTERNAL_SERVER_ERROR,
				));
			}
		}
	}

	Either::Right(HttpResponse::Ok().finish())
}

type ChangePassResponse<'a> = Either<(Json<ApiResponse>, http::StatusCode), HttpResponse>;
