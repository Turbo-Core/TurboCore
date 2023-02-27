use std::collections::BTreeMap;

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

use chrono::{Duration, Utc};
use email::{verification, EmailParams};
use entity::users;
use log::error;
use sea_orm::{ActiveModelTrait, EntityTrait, Set};

use jwt::{SignWithKey, VerifyWithKey};
use uaparser::Parser;
use uuid::Uuid;

#[derive(serde::Deserialize)]
pub struct VerifyBody {
	pub next_url: String,
}

#[post("/api/auth/user/verify-email")]
pub async fn send_handler(
	request: actix_web::HttpRequest,
	data: Data<AppState>,
	body: Json<VerifyBody>,
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

	let uid_str = user.uid.clone().to_string();
	let exp_str = Utc::now().timestamp() + Duration::minutes(15).num_seconds();
	let exp_str = exp_str.to_string();
	let next_url = body.next_url.to_owned();

	let mut claims: BTreeMap<&str, &str> = BTreeMap::new();
	claims.insert("iss", "TurboCore");
	claims.insert("uid", &uid_str);
	claims.insert("exp", &exp_str);
	claims.insert("next", &next_url);

	let token = claims.sign_with_key(&data.config.secret_key).unwrap();

	let action_link = format!("{}/api/auth/user/verify-email/{}", data.config.base_url, token);

	let email_config = data.config.email.to_owned().unwrap();

	let (os, device) = match header_map.get("User-Agent") {
		Some(user_agent) => {
			let a = data.ua_parser.parse_os(user_agent.to_str().unwrap()).family;
			let b = data
				.ua_parser
				.parse_device(user_agent.to_str().unwrap())
				.family;
			(a.to_string(), b.to_string())
		}
		None => ("Unknown".to_string(), "Unknown".to_string()),
	};

	verification::send(EmailParams {
		name: user.email.to_owned(),
		action_url: action_link,
		subject: email_config.confirmation_subject,
		from: email_config.from,
		to: user.email,
		reply_to: email_config.reply_to,
		os,
		device,
		mailer,
	})
	.await;

	Either::Right(HttpResponse::Ok().finish())
}

#[get("/api/auth/user/verify-email/{token}")]
pub async fn receive_handler(data: Data<AppState>, path: Path<String>) -> HttpResponse {
	let token = path.into_inner();

	let claims: BTreeMap<String, String> = match token.verify_with_key(&data.config.secret_key) {
		Ok(claims) => claims,
		Err(_) => {
			return HttpResponse::BadRequest().finish();
		}
	};

	if Utc::now().timestamp() > claims.get("exp").unwrap().parse().unwrap() {
		return HttpResponse::Gone().finish();
	}

	let uid = Uuid::parse_str(claims.get("uid").unwrap()).unwrap();

	let user = match users::Entity::find_by_id(uid).one(&data.connection).await {
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

	let next_url = format!("{}/?verified=true", claims.get("next").unwrap());

	HttpResponse::Found()
		.append_header(("Location", next_url))
		.finish()
}
