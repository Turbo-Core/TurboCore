use crate::{
    auth::{util::get_at_and_rt, ApiResponse},
    AppState,
};
use actix_web::{
    http, post,
    web::{Data, Json},
    Responder,
};
use argon2;
use entity::users;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use serde::Deserialize;

#[derive(Deserialize)]
pub struct LoginBody {
    email: String,
    password: String,
}

#[post("/api/auth/user/login")]
pub async fn handler(data: Data<AppState>, body: Json<LoginBody>) -> impl Responder {
    let user_res = users::Entity::find()
        .filter(users::Column::Email.eq(&body.email))
        .one(&data.connection)
        .await;

    match user_res {
        Ok(user) => {
            match user {
                // User is found
                Some(user) => {
                    if !argon2::verify_encoded(&user.password, body.password.as_bytes()).unwrap() {
                        return (
                            Json(ApiResponse::ApiError {
                                message: "The email or password is invalid".to_string(),
                                error_code: "INVALID_CREDENTIALS".to_string(),
                            }),
                            http::StatusCode::UNAUTHORIZED,
                        );
                    }
                    let uid_str = &user.uid.to_string();
                    let (at, rt, exp) =
                        get_at_and_rt(&data.connection, uid_str, &data.config.secret_key).await;
                    (
                        Json(ApiResponse::LoginResponse {
                            uid: uid_str.to_string(),
                            token: at,
                            expiry: exp,
                            refresh_token: rt,
                            email_verified: user.email_verified,
                            metadata: user.metadata.clone().unwrap_or("".to_string()),
                        }),
                        http::StatusCode::OK,
                    )
                }
                // User is not found
                None => {
                    (
                        Json(ApiResponse::ApiError {
                            message: "The email or password is invalid".to_string(),
                            error_code: "INVALID_CREDENTIALS".to_string(),
                        }),
                        http::StatusCode::UNAUTHORIZED,
                    )
                }
            }
        }
        // Some DBErr occurred. TODO: handle this
        Err(_) => (
            Json(ApiResponse::ApiError {
                message: "Internal server error.".to_string(),
                error_code: "INTERNAL_SERVER_ERROR".to_string(),
            }),
            http::StatusCode::INTERNAL_SERVER_ERROR,
        ),
    }
}
