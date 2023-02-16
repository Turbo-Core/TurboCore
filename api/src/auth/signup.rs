use actix_web::web::{Data, Json};
use actix_web::{http, post, Responder};
use bcrypt::*;
use chrono::Utc;
use entity::users;
use migration::{DbErr, OnConflict};
use sea_orm::{EntityTrait, Set};
use serde::Serialize;
use uuid::Uuid;

use crate::AppState;

#[derive(Debug, Serialize)]
enum ApiResponse {
    ApiError { message: String, error_code: String },
    String,
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
pub async fn handler(
    data: Data<AppState>,
    body: Json<SignupBody>,
) -> impl Responder {
    let user_uid = Uuid::new_v4();

    // TODO: Use hashing cost from config
    let password_hash = hash(body.password.clone(), 12).unwrap();

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
        email_verified: Set(body.email_verified)
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

    println!("{:?}", res);

    match res {
        Ok(_) => (Json(ApiResponse::String), http::StatusCode::OK),
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
