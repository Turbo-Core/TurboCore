use std::{collections::BTreeMap, str::FromStr};

use crate::{
    auth::{util::get_at_and_rt, ApiResponse},
    AppState,
};
use actix_web::{
    http, post,
    web::{Data, Json},
    Responder,
};
use chrono::Utc;
use entity::refresh_tokens::{self, ActiveModel};
use jwt::VerifyWithKey;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, ModelTrait, QueryFilter, Set};
use serde::Deserialize;
use uuid::Uuid;

#[derive(Deserialize)]
pub struct RefreshBody {
    refresh_token: String,
}

#[post("/api/auth/refresh")]
pub async fn handler(data: Data<AppState>, body: Json<RefreshBody>) -> impl Responder {
    let claims: BTreeMap<String, String> =
        match body.refresh_token.verify_with_key(&data.config.secret_key) {
            Ok(c) => c,
            Err(_) => {
                return (
                    Json(ApiResponse::ApiError {
                        message: "The provided JWT could not be verified by the server",
                        error_code: "INVALID_JWT",
                    }),
                    http::StatusCode::UNAUTHORIZED,
                );
            }
        };

    let res = refresh_tokens::Entity::find()
        .filter(refresh_tokens::Column::RefreshToken.eq(&body.refresh_token))
        .one(&data.connection)
        .await;

    let uid = claims.get("uid").unwrap().to_string();

    match res {
        Err(err) => match err {
            sea_orm::error::DbErr::RecordNotFound(_) => {
                // RT is not in DB, likely very old, all RTs should be revoked
                let uid = Uuid::from_str(&uid).unwrap();
                refresh_tokens::Entity::delete_many()
                    .filter(refresh_tokens::Column::Uid.eq(uid))
                    .exec(&data.connection)
                    .await
                    .unwrap();
            }
            _ => {
                return (
                    Json(ApiResponse::ApiError {
                        message: "Internal Server Error",
                        error_code: "INTERNAL_SERVER_ERROR",
                    }),
                    http::StatusCode::INTERNAL_SERVER_ERROR,
                );
            }
        },
        Ok(rt_model) => {
            match rt_model {
                Some(rt) => {
                    if rt.used {
                        // Again, revoke all RTs, it has been used
                        let uid = Uuid::from_str(&uid).unwrap();
                        refresh_tokens::Entity::delete_many()
                            .filter(refresh_tokens::Column::Uid.eq(uid))
                            .exec(&data.connection)
                            .await;
                        return (
                            Json(ApiResponse::ApiError {
                                message:
                                    "The JWT provided has already expired. Please log in again",
                                error_code: "EXPIRED_JWT",
                            }),
                            http::StatusCode::UNAUTHORIZED,
                        );
                    }

                    if Utc::now().timestamp() < claims.get("exp").unwrap().parse().unwrap() {
                        // First, mark the old token as used
                        let mut rt_update: ActiveModel = rt.into();
                        rt_update.used = Set(true);
                        rt_update.update(&data.connection).await;

                        // Here is the only time we issue a new token, when not expired, and not used
                        let (at, rt, exp) =
                            get_at_and_rt(&data.connection, &uid, &data.config.secret_key).await;

                        return (
                            Json(ApiResponse::RefreshResponse {
                                uid: uid,
                                access_token: at,
                                refresh_token: rt,
                                expiry: exp,
                            }),
                            http::StatusCode::OK,
                        );
                    }
                }
                None => {
                    // RT is not in DB, likely very old, all RTs should be revoked
                    let uid = Uuid::from_str(&uid).unwrap();
                    refresh_tokens::Entity::delete_many()
                        .filter(refresh_tokens::Column::Uid.eq(uid))
                        .exec(&data.connection)
                        .await;
                }
            }
        }
    }
    return (
        Json(ApiResponse::ApiError {
            message: "The JWT provided has already expired. Please log in again",
            error_code: "EXPIRED_JWT",
        }),
        http::StatusCode::UNAUTHORIZED,
    );
}
