use crate::auth::{util, ApiResponse};
use actix_web::{http, post, Responder, web::{Data, Json}};
use argon2::{self, Config as ArgonConfig, ThreadMode, Variant, Version};
use chrono::Utc;
use entity::users;
use migration::{DbErr, OnConflict};
use rand::{thread_rng, Rng};
use sea_orm::{EntityTrait, Set};
use uuid::Uuid;

use crate::AppState;

// TODO: Implement error handling: https://actix.rs/docs/extractors#json
#[derive(serde::Deserialize)]
pub struct SignupBody {
    email: String,
    password: String,
    email_verified: bool,
    login: bool,
    metadata: String,
}

#[post("/api/auth/user/create")]
pub async fn handler(data: Data<AppState>, body: Json<SignupBody>) -> impl Responder {
    // Get uid for new user
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

    // TODO: Vulnerable until sanitize middleware is implemented
    let new_user = users::ActiveModel {
        uid: Set(user_uid),
        email: Set(body.email.to_owned()),
        password: Set(password_hash),
        created_at: Set(Utc::now().naive_utc()),
        last_login: Set(None),
        updated_at: Set(Utc::now().naive_utc()),
        active: Set(true),
        metadata: Set(Some(body.metadata.to_owned())),
        email_verified: Set(body.email_verified),
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
                    util::get_at_and_rt(&data.connection, &uid_str, &data.config.secret_key).await;

                (
                    Json(ApiResponse::LoginResponse {
                        uid: uid_str,
                        token: token_str,
                        expiry: short_exp,
                        refresh_token: rt_str,
                        email_verified: body.email_verified,
                        metadata: body.metadata.clone(),
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
            Json(ApiResponse::ApiError {
                message: "This email is already in use.",
                error_code: "EMAIL_ALREADY_IN_USE",
            }),
            http::StatusCode::CONFLICT,
        ),
        _ => (
            Json(ApiResponse::ApiError {
                message: "Internal Server Error",
                error_code: "INTERNAL_ERROR",
            }),
            http::StatusCode::INTERNAL_SERVER_ERROR,
        ),
    }
}
