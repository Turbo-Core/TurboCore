use crate::{auth::ApiResponse, AppState};
use actix_web::{
    get, http,
    web::{Data, Json},
    Responder,
};
use entity::users;
use log::info;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use crate::auth::util;

use super::util::HeaderResult;

#[get("/api/auth/user")]
pub async fn handler(request: actix_web::HttpRequest, data: Data<AppState>) -> impl Responder {
    let header_map = request.headers();
    let authorization = header_map.get("Authorization");

    let uid = match util::verify_header(authorization, &data.config.secret_key) {
        HeaderResult::Error(r, s) => {
            return (r, s);
        }
        HeaderResult::Uid(uid) => uid
    };

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