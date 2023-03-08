use crate::{
	auth::{
		api_error,
		util::{self, HeaderResult},
	},
	AppState,
};
use actix_web::{
	http, post,
	web::{Data, Json},
	Either, HttpResponse,
};
use entity::refresh_tokens;
use log::error;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};

use super::ApiResponse;

#[derive(serde::Deserialize)]
pub struct LogoutBody {
	refresh_token: Option<String>,
}

#[post("/api/auth/user/logout")]
pub async fn handler(
	request: actix_web::HttpRequest,
	body: Json<LogoutBody>,
	data: Data<AppState>,
) -> DeleteUserResponse<'static> {
	let header_map = request.headers();
	let authorization = header_map.get("Authorization");

	let uid = match util::verify_header(authorization, &data.config.secret_key) {
		HeaderResult::Error(r, s) => {
			return Either::Left((r, s));
		}
		HeaderResult::Uid(uid) => uid,
	};

	// If the refresh token is provided, delete it. Otherwise, delete all refresh tokens for the user
	match body.refresh_token.clone() {
		Some(token) => {
			match refresh_tokens::Entity::delete_by_id(&token)
				.exec(&data.connection)
				.await
			{
				Ok(_) => Either::Right(HttpResponse::Ok().finish()),
				Err(e) => {
					error!("Failed to delete refresh token {}. Error: {}", token, e.to_string());
					Either::Left((
						Json(api_error(
							"Internal Server Error".to_string(),
							"INTERNAL_SERVER_ERROR".to_string(),
						)),
						http::StatusCode::INTERNAL_SERVER_ERROR,
					))
				}
			}
		}
		None => {
			match refresh_tokens::Entity::delete_many()
				.filter(refresh_tokens::Column::Uid.eq(uid))
				.exec(&data.connection)
				.await
			{
				Ok(_) => Either::Right(HttpResponse::Ok().finish()),
				Err(e) => {
					error!(
						"Failed to delete refresh tokens for {}. Error: {}",
						uid.to_string(),
						e.to_string()
					);
					Either::Left((
						Json(api_error(
							"Internal Server Error".to_string(),
							"INTERNAL_SERVER_ERROR".to_string(),
						)),
						http::StatusCode::INTERNAL_SERVER_ERROR,
					))
				}
			}
		}
	}
}

type DeleteUserResponse<'a> = Either<(Json<ApiResponse>, http::StatusCode), HttpResponse>;
