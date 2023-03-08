use std::collections::BTreeMap;

use crate::{
	auth::{api_error, util::get_at_and_rt, ApiResponse},
	AppState,
};
use actix_web::{
	get, http, post,
	web::{Data, Json, Path},
	Either, HttpResponse,
};

use chrono::{Duration, NaiveDateTime, Utc};
use email::{magic, EmailParams};
use entity::users;
use jwt::{SignWithKey, VerifyWithKey};
use log::error;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};
use uaparser::Parser;
use uuid::Uuid;

#[derive(serde::Deserialize)]
pub struct MagicBody {
	pub next_url: String,
	pub email: String,
	pub sign_up: bool,
}

#[post("/api/auth/user/magic-link")]
pub async fn post_handler(
	request: actix_web::HttpRequest,
	data: Data<AppState>,
	body: Json<MagicBody>,
) -> Either<(Json<ApiResponse>, http::StatusCode), HttpResponse> {
	if data.config.mailer.is_none() || data.config.email.is_none() {
		return Either::Left((
			Json(api_error(
				"The server is not configured to send emails.".to_string(),
				"EMAIL_NOT_CONFIGURED".to_string(),
			)),
			http::StatusCode::BAD_REQUEST,
		));
	}

	let user = match users::Entity::find()
		.filter(users::Column::Email.eq(body.email.to_owned()))
		.one(&data.connection)
		.await
	{
		Ok(user) => match user {
			Some(user) => {
				if body.sign_up {
					return Either::Left((
						Json(api_error(
							"The user already exists.".to_string(),
							"USER_ALREADY_EXISTS".to_string(),
						)),
						http::StatusCode::BAD_REQUEST,
					));
				}
				user
			}
			None => {
				if !body.sign_up {
					return Either::Left((
						Json(api_error(
							"The user does not exist.".to_string(),
							"USER_DOES_NOT_EXIST".to_string(),
						)),
						http::StatusCode::BAD_REQUEST,
					));
				}
				let uid = Uuid::new_v4();
				let now = NaiveDateTime::from_timestamp_opt(Utc::now().timestamp(), 0).unwrap();
				let new_user = users::ActiveModel {
					uid: Set(uid),
					password: Set("0".to_string()),
					email: Set(body.email.to_owned()),
					created_at: Set(now),
					updated_at: Set(now),
					active: Set(true),
					email_verified: Set(false),
					..Default::default()
				};
				let new_user = new_user.insert(&data.connection).await;
				match new_user {
					Ok(user) => user,
					Err(e) => {
						error!("Unable to create user. Error: {}", e.to_string());
						return Either::Left((
							Json(api_error(
								"Internal Server Error".to_string(),
								"INTERNAL_SERVER_ERROR".to_string(),
							)),
							http::StatusCode::INTERNAL_SERVER_ERROR,
						));
					}
				}
			}
		},
		Err(e) => {
			error!("Unable to find user. Error: {}", e.to_string());
			return Either::Left((
				Json(api_error(
					"Internal Server Error".to_string(),
					"INTERNAL_SERVER_ERROR".to_string(),
				)),
				http::StatusCode::INTERNAL_SERVER_ERROR,
			));
		}
	};

	let mut claims: BTreeMap<&str, &str> = BTreeMap::new();
	let uid_str = user.uid.to_string();
	let exp = (Utc::now().timestamp() + Duration::minutes(15).num_seconds()).to_string();
	claims.insert("iss", "TurboCore");
	claims.insert("type", "magic-link");
	claims.insert("uid", &uid_str);
	claims.insert("exp", &exp);
	claims.insert("next", &body.next_url);

	let token = claims.sign_with_key(&data.config.secret_key).unwrap();

	let action_url = format!("{}/api/auth/user/magic-link/{}", data.config.base_url, token);

	let mailer = data.config.mailer.as_ref().unwrap();

	let email_config = data.config.email.to_owned().unwrap();

	let header_map = request.headers();
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

	magic::send(EmailParams {
		name: user.email.to_owned(),
		action_url,
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

#[get("/api/auth/user/magic-link/{uid}")]
pub async fn get_handler(data: Data<AppState>, path: Path<String>) -> HttpResponse {
	let token = path.into_inner();
	let claims: BTreeMap<String, String> = match token.verify_with_key(&data.config.secret_key) {
		Ok(claims) => claims,
		Err(e) => {
			error!("Unable to verify token. Error: {}", e.to_string());
			return HttpResponse::BadRequest().json(api_error(
				"The provided was invalid.".to_string(),
				"INVALID_TOKEN".to_string(),
			));
		}
	};

	if Utc::now().timestamp() > claims["exp"].parse::<i64>().unwrap() {
		return HttpResponse::BadRequest().json(api_error(
			"The token has already expired".to_string(),
			"EXPIRED_TOKEN".to_string(),
		));
	}

	if claims["type"] != "magic-link" {
		return HttpResponse::BadRequest().json(api_error(
			"The provided token is invalid.".to_string(),
			"INVALID_TOKEN".to_string(),
		));
	}

	let uid = Uuid::parse_str(&claims["uid"]).unwrap();

	let user = match users::Entity::find()
		.filter(users::Column::Uid.eq(uid))
		.one(&data.connection)
		.await
	{
		Ok(user) => match user {
			Some(user) => user,
			None => {
				return HttpResponse::BadRequest().json(api_error(
					"The user does not exist.".to_string(),
					"USER_DOES_NOT_EXIST".to_string(),
				));
			}
		},
		Err(e) => {
			error!("Unable to find user. Error: {}", e.to_string());
			return HttpResponse::InternalServerError().json(api_error(
				"Internal Server Error".to_string(),
				"INTERNAL_SERVER_ERROR".to_string(),
			));
		}
	};

	let (at, rt, exp) =
		get_at_and_rt(&data.connection, &user.uid.to_string(), &data.config.secret_key).await;

	let redirect_url =
		format!("{}?uid={}?at={}&rt={}&exp={}", user.uid, claims["next"], at, rt, exp);

	HttpResponse::Found()
		.append_header(("Location", redirect_url))
		.finish()
}
