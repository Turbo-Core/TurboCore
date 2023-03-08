use crate::auth::{api_error, util};
use crate::{auth::ApiResponse, AppState};
use actix_web::{
	get, http,
	web::{Data, Json},
	Responder,
};
use entity::users;
use log::info;
use sea_orm::EntityTrait;

use super::util::HeaderResult;

#[get("/api/auth/user")]
pub async fn handler(request: actix_web::HttpRequest, data: Data<AppState>) -> impl Responder {
	let header_map = request.headers();
	let authorization = header_map.get("Authorization");

	let uid = match util::verify_header(authorization, &data.config.secret_key) {
		HeaderResult::Error(r, s) => {
			return (r, s);
		}
		HeaderResult::Uid(uid) => uid,
	};

	let user = users::Entity::find_by_id(uid).one(&data.connection).await;

	match user {
		Ok(user) => match user {
			Some(user) => (
				Json(ApiResponse::UserResponse {
					uid: user.uid.to_string(),
					email: user.email,
					created_at: user.created_at,
					updated_at: user.updated_at,
					last_login: user.last_login,
					active: user.active,
					metadata: user.metadata,
					email_verified: user.email_verified,
				}),
				http::StatusCode::OK,
			),
			None => (
				Json(api_error(
					"The user was not found.".to_string(),
					"USER_NOT_FOUND".to_string(),
				)),
				http::StatusCode::NOT_FOUND,
			),
		},
		Err(err) => {
			info!("{}", err.to_string());
			(
				Json(api_error(
					"An internal server error occurred.".to_string(),
					"INTERNAL_SERVER_ERROR".to_string(),
				)),
				http::StatusCode::INTERNAL_SERVER_ERROR,
			)
		}
	}
}
