use std::{collections::BTreeMap, str::FromStr};

use crate::{auth::ApiResponse, AppState};
use actix_web::{
    get, http,
    web::{Data, Json},
    Responder,
};
use chrono::Utc;
use entity::users;
use jwt::VerifyWithKey;
use log::info;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use uuid::Uuid;

#[get("/api/auth/user")]
pub async fn handler(request: actix_web::HttpRequest, data: Data<AppState>) -> impl Responder {
    let header_map = request.headers();
    let authorization = header_map.get("Authorization");

    let authorization = match authorization {
        Some(a) => {
            match a.to_str() {
                Ok(s) => s,
                Err(_e) => {
                    // TODO: Should this be logged? See [ToStrError]
                    return (
                        Json(ApiResponse::ApiError {
                            message: "The request contains headers with opaque bytes.",
                            error_code: "BAD_HEADER",
                        }),
                        http::StatusCode::BAD_REQUEST,
                    );
                }
            }
        }
        None => {
            return (
                Json(ApiResponse::ApiError {
                    message: "The request is missing an 'Authorization' header",
                    error_code: "NOT_AUTHENTICATED",
                }),
                http::StatusCode::UNAUTHORIZED,
            )
        }
    };

    let parts: Vec<&str> = authorization.split_whitespace().collect();
    if parts[0] != "Bearer" && parts[0] != "bearer" {
        return (
            Json(ApiResponse::ApiError {
                message: "The 'Authorization' header is improperly formatted",
                error_code: "BAD_HEADER",
            }),
            http::StatusCode::BAD_REQUEST,
        );
    }
    let token = match parts.get(1) {
        Some(token) => *token,
        None => {
            return (
                Json(ApiResponse::ApiError {
                    message: "The 'Authorization' header is improperly formatted",
                    error_code: "BAD_HEADER",
                }),
                http::StatusCode::BAD_REQUEST,
            );
        }
    };

    let claims: BTreeMap<String, String> = match token.verify_with_key(&data.config.secret_key) {
        Ok(c) => c,
        Err(_) => {
            return (
                Json(ApiResponse::ApiError {
                    message: "The JWT could not be verified by the server",
                    error_code: "BAD_TOKEN",
                }),
                http::StatusCode::UNAUTHORIZED,
            );
        }
    };

    if Utc::now().timestamp() > claims.get("exp").unwrap().parse().unwrap() {
        return (
            Json(ApiResponse::ApiError {
                message: "The JWT has already expired",
                error_code: "BAD_TOKEN",
            }),
            http::StatusCode::UNAUTHORIZED,
        );
    }

    let uid = &claims.get("uid").unwrap()[..];

    let uid = Uuid::from_str(uid).unwrap();

    // Wow that was a lot of checks. If they all passed, then return the user's information
    let user = users::Entity::find()
        .filter(users::Column::Uid.eq(uid))
        .one(&data.connection)
        .await;

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
                Json(ApiResponse::ApiError {
                    message: "The requested user was not found",
                    error_code: "USER_NOT_FOUND",
                }),
                http::StatusCode::NOT_FOUND,
            ),
        },
        Err(err) => {
            info!("{}", err.to_string());
            (
            Json(ApiResponse::ApiError {
                message: "Something went wrong",
                error_code: "INTERNAL_SERVER_ERROR",
            }),
            http::StatusCode::INTERNAL_SERVER_ERROR,
        )
    },
    }
}