use actix_web::web::{Data, Json};
use actix_web::{http, post, Responder};
use argon2::{self, Config as ArgonConfig, ThreadMode, Variant, Version};
use chrono::Utc;
use entity::users;
use jwt::SignWithKey;
use migration::{DbErr, OnConflict};
use rand::{thread_rng, Rng, RngCore};
use sea_orm::{EntityTrait, Set};
use serde::Serialize;
use std::collections::BTreeMap;
use uuid::Uuid;

use crate::AppState;

#[derive(Debug, Serialize)]
enum ApiResponse {
    ApiError {
        message: String,
        error_code: String,
    },
    NoLoginResponse {
        uid: String,
    },
    LoginResponse {
        uid: String,
        token: String,
        expiry: u32,
        refresh_token: String,
        email_verified: bool,
        metadata: String,
    },
}

// TODO: Implement error handling: https://actix.rs/docs/extractors#json
#[derive(serde::Deserialize)]
pub struct SignupBody {
    email: String,
    password: String,
    email_verified: bool,
    login: bool,
    metadata: String,
}

#[post("/api/auth/signup")]
pub async fn handler(data: Data<AppState>, body: Json<SignupBody>) -> impl Responder {
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

    println!("{}", data.config.argon2_config.memory);

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
                let mut token = BTreeMap::new();
                let mut refresh_token = BTreeMap::new();

                // TODO: make exp configurable
                // The RFC protocol allows for some lee way ("up to a few minutes") in exp, hence +15 seconds
                let short_exp = Utc::now().timestamp() as u32 + 15 * 60 + 15;
                let short_exp_str = short_exp.to_string();
                let long_exp = (Utc::now().timestamp() + 60 * 60 * 24 * 7).to_string();

                let uid_str = user_uid.to_string();

                refresh_token.insert("iss", "TurboCore");
                refresh_token.insert("exp", &long_exp);
                refresh_token.insert("uid", &uid_str);

                token.insert("iss", "TurboCore");
                token.insert("exp", &short_exp_str);
                token.insert("uid", &uid_str);

                let token_str = token.sign_with_key(&data.config.secret_key).unwrap();
                let rt_str = refresh_token
                    .sign_with_key(&data.config.secret_key)
                    .unwrap();
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
                    Json(ApiResponse::NoLoginResponse {
                        uid: user_uid.to_string(),
                    }),
                    http::StatusCode::CREATED,
                )
            }
        }
        Err(DbErr::RecordNotInserted) => (
            Json(ApiResponse::ApiError {
                message: "This email is already in use.".to_string(),
                error_code: "EMAIL_ALREADY_IN_USE".to_string(),
            }),
            http::StatusCode::CONFLICT,
        ),
        _ => (
            Json(ApiResponse::ApiError {
                message: "Internal Server Error".to_string(),
                error_code: "INTERNAL_ERROR".to_string(),
            }),
            http::StatusCode::INTERNAL_SERVER_ERROR,
        ),
    }
}
