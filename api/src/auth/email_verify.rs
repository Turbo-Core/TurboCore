use crate::{
	auth::{
		util::{self, HeaderResult},
		ApiResponse,
	},
	AppState,
};
use actix_web::{
	get, http, post,
	web::{Data, Json, Path},
	Either, HttpResponse,
};

use chrono::{Duration, NaiveDateTime, Utc};
use email::{verification, EmailParams};
use entity::{email_verification, users};
use log::error;
use sea_orm::{ActiveModelTrait, EntityTrait, Set};
use uuid::Uuid;

#[post("/api/auth/user/verify-email")]
pub async fn send_handler(
	request: actix_web::HttpRequest,
	data: Data<AppState>,
) -> Either<(Json<ApiResponse>, http::StatusCode), HttpResponse> {
	let header_map = request.headers();
	let authorization = header_map.get("Authorization");

	let uid = match util::verify_header(authorization, &data.config.secret_key) {
		HeaderResult::Error(r, s) => {
			return Either::Left((r, s));
		}
		HeaderResult::Uid(uid) => uid,
	};

	let user = match users::Entity::find_by_id(uid).one(&data.connection).await {
		Ok(user) => match user {
			Some(user) => user,
			None => {
				return Either::Left((
					Json(ApiResponse::ApiError {
						message: "The user was not found".to_string(),
						error_code: "USER_NOT_FOUND".to_string(),
					}),
					http::StatusCode::NOT_FOUND,
				));
			}
		},
		Err(e) => {
			error!("Unable to find user. Error: {}", e.to_string());
			return Either::Left((
				Json(ApiResponse::ApiError {
					message: "Internal Server Error".to_string(),
					error_code: "INTERNAL_SERVER_ERROR".to_string(),
				}),
				http::StatusCode::INTERNAL_SERVER_ERROR,
			));
		}
	};

	if user.email_verified {
		return Either::Left((
			Json(ApiResponse::ApiError {
				message: "The user is already verified.".to_string(),
				error_code: "ALREADY_VERIFIED".to_string(),
			}),
			http::StatusCode::BAD_REQUEST,
		));
	}

	if data.config.mailer.is_none() || data.config.email.is_none() {
		return Either::Left((
			Json(ApiResponse::ApiError {
				message: "The server is not configured to send emails.".to_string(),
				error_code: "EMAIL_NOT_CONFIGURED".to_string(),
			}),
			http::StatusCode::BAD_REQUEST,
		));
	}

	let mailer = data.config.mailer.as_ref().unwrap();

	let token = Uuid::new_v4().to_string();

	let mut action_link = data.config.base_url.to_owned();
	action_link.push_str("/api/auth/user/verify-email");
	action_link.push_str(&token);

	match (email_verification::ActiveModel {
		uid: Set(user.uid),
		token: Set(token),
		expiry: Set(NaiveDateTime::from_timestamp_opt(
			Utc::now().timestamp() + Duration::minutes(15).num_seconds(),
			0,
		)
		.unwrap()),
		next: Set(data.config.base_url.to_owned()),
	}
	.insert(&data.connection)
	.await)
	{
		Ok(_) => (),
		Err(e) => {
			error!("Unable to insert email verification token. Error: {}", e.to_string());
			return Either::Left((
				Json(ApiResponse::ApiError {
					message: "Internal Server Error".to_string(),
					error_code: "INTERNAL_SERVER_ERROR".to_string(),
				}),
				http::StatusCode::INTERNAL_SERVER_ERROR,
			));
		}
	}

	let email_config = data.config.email.to_owned().unwrap();

	verification::send(EmailParams {
		name: user.email.to_owned(),
		action_url: action_link,
		subject: email_config.confirmation_subject,
		from: email_config.from,
		to: user.email,
		reply_to: email_config.reply_to,
		mailer,
	})
	.await;

	Either::Right(HttpResponse::Ok().finish())
}

#[get("/api/auth/user/verify-email/{token}")]
pub async fn receive_handler(data: Data<AppState>, path: Path<String>) -> HttpResponse {
	let token = path.into_inner();

	let verification = match email_verification::Entity::find_by_id(&token)
		.one(&data.connection)
		.await
	{
		Ok(verification) => match verification {
			Some(verification) => verification,
			None => {
				return HttpResponse::NotFound().finish();
			}
		},
		Err(_) => {
			return HttpResponse::NotFound().finish();
		}
	};

	if verification.expiry < Utc::now().naive_utc() {
		return HttpResponse::Gone().finish();
	}

	let user = match users::Entity::find_by_id(verification.uid)
		.one(&data.connection)
		.await
	{
		Ok(user) => match user {
			Some(user) => user,
			None => {
				return HttpResponse::NotFound().finish();
			}
		},
		Err(_) => {
			return HttpResponse::NotFound().finish();
		}
	};

	let mut user: users::ActiveModel = user.into();
	user.email_verified = Set(true);

	match user.update(&data.connection).await {
		Ok(_) => (),
		Err(e) => {
			error!("Unable to update user email verification status. Error: {}", e.to_string());
			return HttpResponse::InternalServerError().finish();
		}
	}

	match email_verification::Entity::delete_by_id(&token)
		.exec(&data.connection)
		.await
	{
		Ok(_) => (),
		Err(e) => {
			error!("Unable to delete email verification token. Error: {}", e.to_string());
			return HttpResponse::InternalServerError().finish();
		}
	}

	HttpResponse::Ok()
		.insert_header(("Location", verification.next))
		.finish()
}
