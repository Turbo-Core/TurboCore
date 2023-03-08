use actix_web::{
	http, put,
	web::{Data, Json},
	Either, HttpResponse,
};
use entity::users::{self, ActiveModel};
use log::error;
use sea_orm::{ActiveModelTrait, EntityTrait, Set};

use crate::{
	auth::{
		api_error,
		util::{self, HeaderResult},
		ApiResponse,
	},
	AppState,
};

#[derive(serde::Deserialize)]
pub struct UpdateUserBody {
	email: Option<String>,
	metadata: Option<Metadata>,
}

#[derive(serde::Deserialize)]
enum Metadata {
	Data(String),
	None,
}

#[put("/api/auth/user")]
pub async fn handler(
	request: actix_web::HttpRequest,
	data: Data<AppState>,
	body: Json<UpdateUserBody>,
) -> Either<(Json<ApiResponse>, http::StatusCode), HttpResponse> {
	let header_map = request.headers();
	let authorization = header_map.get("Authorization");

	let uid = match util::verify_header(authorization, &data.config.secret_key) {
		HeaderResult::Error(r, s) => {
			return Either::Left((r, s));
		}
		HeaderResult::Uid(uid) => uid,
	};

	let user = users::Entity::find_by_id(uid).one(&data.connection).await;
	let user = match user {
		Ok(user) => match user {
			Some(user) => user,
			None => {
				return Either::Left((
					Json(api_error(
						"The user was not found.".to_string(),
						"USER_NOT_FOUND".to_string(),
					)),
					http::StatusCode::BAD_REQUEST,
				));
			}
		},
		Err(e) => {
			error!("Error finding user: {}", e);
			return Either::Left((
				Json(api_error(
					"An internal server error occurred.".to_string(),
					"INTERNAL_SERVER_ERROR".to_string(),
				)),
				http::StatusCode::INTERNAL_SERVER_ERROR,
			));
		}
	};

	let mut user: ActiveModel = user.into();

	if let Some(email) = body.email.to_owned() {
		user.email = Set(email);
	}

	if let Some(metadata) = &body.metadata {
		match metadata {
			Metadata::Data(data) => user.metadata = Set(Some(data.to_string())),
			Metadata::None => user.metadata = Set(None),
		}
	}

	match user.update(&data.connection).await {
		Ok(_) => (),
		Err(e) => {
			error!("Error updating user: {}", e);
			return Either::Left((
				Json(api_error(
					"An internal server error occurred.".to_string(),
					"INTERNAL_SERVER_ERROR".to_string(),
				)),
				http::StatusCode::INTERNAL_SERVER_ERROR,
			));
		}
	};

	Either::Right(HttpResponse::Ok().finish())
}
