extern crate zxcvbn;

use crate::auth::{api_error, util, ApiResponse};
use actix_web::{
	http, post,
	web::{Data, Json},
	Responder,
};
use argon2::{self, Config as ArgonConfig, ThreadMode, Variant, Version};
use chrono::Utc;
use entity::users;
use migration::{DbErr, OnConflict};
use rand::{thread_rng, Rng};
use sea_orm::{EntityTrait, Set};
use uuid::Uuid;
use zxcvbn::zxcvbn;

use crate::AppState;

#[derive(serde::Deserialize)]
pub struct SignupBody {
	email: String,
	password: String,
	login: bool,
}

#[post("/api/admin/create")]
pub async fn handler(data: Data<AppState>, body: Json<SignupBody>) -> impl Responder {
	// Check password strength
	let estimate = match zxcvbn(&body.password, &[]) {
		Ok(ent) => ent,
		Err(_) => {
			return (
				Json(api_error(
					"An invalid password was provided.".to_string(),
					"INVALID_PASSWORD".to_string(),
				)),
				http::StatusCode::BAD_REQUEST,
			);
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
		return (
			Json(api_error(feedback_msg, "WEAK_PASSWORD".to_string())),
			http::StatusCode::BAD_REQUEST,
		);
	}

	// Get uid for new admin
	let user_uid = Uuid::new_v4();

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
		argon2::hash_encoded(body.password.as_bytes(), salt.as_slice(), &config).unwrap();

	// FIXME: Vulnerable until sanitize middleware is implemented
	let new_user = users::ActiveModel {
		uid: Set(user_uid),
		email: Set(body.email.to_owned()),
		password: Set(password_hash),
		created_at: Set(Utc::now().naive_utc()),
		last_login: Set(None),
		updated_at: Set(Utc::now().naive_utc()),
		active: Set(true),
		metadata: Set(Some("".to_string())),
		email_verified: Set(true),
        is_admin: Set(true),
	};

	let res = users::Entity::insert(new_user)
		.on_conflict(
			// If email exists, we will ignore the request to create a new user, causing a DbErr::RecordNotInserted
			OnConflict::column(users::Column::Email)
				.do_nothing()
				.to_owned(),
		)
		.exec(&data.connection)
		.await;

	match res {
		Ok(_) => {
			if body.login {
				let uid_str = user_uid.to_string();

				let (token_str, rt_str, short_exp) =
					util::get_at_and_rt(&data.connection, &uid_str, &data.config.secret_key, true).await;

				(
					Json(ApiResponse::LoginResponse {
						uid: uid_str,
						token: token_str,
						expiry: short_exp,
						refresh_token: rt_str,
						email_verified: true,
						metadata: "".to_string(),
					}),
					http::StatusCode::CREATED,
				)
			} else {
				(
					Json(ApiResponse::SignupResponse {
						uid: user_uid.to_string(),
					}),
					http::StatusCode::CREATED,
				)
			}
		}
		Err(DbErr::RecordNotInserted) => (
			Json(api_error(
				"The email provided is already in use.".to_string(),
				"EMAIL_IN_USE".to_string(),
			)),
			http::StatusCode::CONFLICT,
		),
		_ => (
			Json(api_error(
				"Internal Server Error.".to_string(),
				"INTERNAL_SERVER_ERROR".to_string(),
			)),
			http::StatusCode::INTERNAL_SERVER_ERROR,
		),
	}
}
