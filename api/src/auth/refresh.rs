use std::{collections::BTreeMap, str::FromStr};

use crate::{
	auth::{util::get_at_and_rt, ApiResponse},
	AppState,
};
use actix_web::{
	http, post,
	web::{Data, Json},
	Responder,
};
use chrono::Utc;
use entity::refresh_tokens::{self, ActiveModel};
use jwt::VerifyWithKey;
use log::error;
use sea_orm::{ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, Set};
use serde::Deserialize;
use uuid::Uuid;

#[derive(Deserialize)]
pub struct RefreshBody {
	refresh_token: String,
}

#[post("/api/auth/user/refresh")]
pub async fn handler(data: Data<AppState>, body: Json<RefreshBody>) -> impl Responder {
	let claims: BTreeMap<String, String> =
		match body.refresh_token.verify_with_key(&data.config.secret_key) {
			Ok(c) => c,
			Err(_) => {
				return (
					Json(ApiResponse::ApiError {
						message: "The provided JWT could not be verified by the server".to_string(),
						error_code: "INVALID_JWT".to_string(),
					}),
					http::StatusCode::UNAUTHORIZED,
				);
			}
		};

	let res = refresh_tokens::Entity::find()
		.filter(refresh_tokens::Column::RefreshToken.eq(&body.refresh_token))
		.one(&data.connection)
		.await;

	let uid = claims.get("uid").unwrap().to_string();

	match res {
		Err(err) => match err {
			sea_orm::error::DbErr::RecordNotFound(_) => {
				let uid = Uuid::from_str(&uid).unwrap();
				// RT is not in DB, likely very old, all RTs should be revoked
				refresh_tokens::Entity::delete_many()
					.filter(refresh_tokens::Column::Uid.eq(uid))
					.exec(&data.connection)
					.await
					.unwrap();
			}
			_ => {
				error!("Database error: {}", err.to_string());
				return (
					Json(ApiResponse::ApiError {
						message: "Internal Server Error".to_string(),
						error_code: "INTERNAL_SERVER_ERROR".to_string(),
					}),
					http::StatusCode::INTERNAL_SERVER_ERROR,
				);
			}
		},
		Ok(rt_model) => {
			match rt_model {
				Some(rt) => {
					if rt.used {
						// Again, revoke all RTs, it has been used
						delete_old_rt(&uid, &data.connection).await;
						return (
							Json(ApiResponse::ApiError {
								message:
									"The JWT provided has already expired. Please log in again"
										.to_string(),
								error_code: "EXPIRED_JWT".to_string(),
							}),
							http::StatusCode::UNAUTHORIZED,
						);
					}

					if Utc::now().timestamp() < claims.get("exp").unwrap().parse().unwrap() {
						// First, mark the old token as used
						let mut rt_update: ActiveModel = rt.into();
						rt_update.used = Set(true);
						match rt_update.update(&data.connection).await {
							Ok(_) => (),
							Err(_) => log::error!("Failed to mark refresh token as used"),
						}

						// Here is the only time we issue a new token, when not expired, and not used
						let (access_token, refresh_token, expiry) =
							get_at_and_rt(&data.connection, &uid, &data.config.secret_key).await;

						return (
							Json(ApiResponse::RefreshResponse {
								uid,
								access_token,
								refresh_token,
								expiry,
							}),
							http::StatusCode::OK,
						);
					}
				}
				None => {
					// Record not found, revoke all RTs
					delete_old_rt(&uid, &data.connection).await;
				}
			}
		}
	}
	(
		Json(ApiResponse::ApiError {
			message: "The JWT provided has already expired. Please log in again".to_string(),
			error_code: "EXPIRED_JWT".to_string(),
		}),
		http::StatusCode::UNAUTHORIZED,
	)
}

async fn delete_old_rt(uid: &str, connection: &DatabaseConnection) {
	let uid = Uuid::from_str(uid).unwrap();
	// RT is not in DB, likely very old, all RTs should be revoked
	match refresh_tokens::Entity::delete_many()
		.filter(refresh_tokens::Column::Uid.eq(uid))
		.exec(connection)
		.await
	{
		Ok(_) => (),
		Err(e) => log::error!("Failed to delete old refresh tokens: {}", e.to_string()),
	}
}
