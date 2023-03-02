use std::collections::BTreeMap;

use actix_web::{
	http, post,
	web::{Data, Json}, Either, HttpResponse,
};
use chrono::{Utc, Duration};
use jwt::SignWithKey;
use log::error;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use serde::Deserialize;
use entity::users;
use uaparser::Parser;
use email::{forgot_password, EmailParams};

use crate::{AppState, auth::ApiResponse};

#[derive(Deserialize)]
pub struct ResetPasswordRequest {
	pub email: String,
	pub reset_url: String,
}

#[post("/api/auth/user/reset-password")]
pub async fn handler(
    request: actix_web::HttpRequest,
	data: Data<AppState>,
	body: Json<ResetPasswordRequest>,
) -> Either<(Json<ApiResponse>, http::StatusCode), HttpResponse> {
    let header_map = request.headers();

    // Check if the server is configured to send emails
	if data.config.mailer.is_none() || data.config.email.is_none() {
		return Either::Left((
			Json(ApiResponse::ApiError {
				message: "The server is not configured to send emails.".to_string(),
				error_code: "EMAIL_NOT_CONFIGURED".to_string(),
			}),
			http::StatusCode::BAD_REQUEST,
		));
	}
    let email_config = data.config.email.to_owned().unwrap();
    let mailer = data.config.mailer.as_ref().unwrap();

    // Lookup the user by email
    let res = users::Entity::find().filter(users::Column::Email.eq(body.email.clone())).one(&data.connection).await;

    let user = match res {
        Ok(user) => match user {
            Some(user) => user,
            None => {
                // If the user is not found, return a 200 response to prevent email enumeration
                return Either::Right(HttpResponse::Ok().finish());
            }
        },
        Err(e) => {
            error!("Unable to find user. Database Error: {}", e.to_string());
            return Either::Left((
                Json(ApiResponse::ApiError {
                    message: "Internal Server Error".to_string(),
                    error_code: "INTERNAL_SERVER_ERROR".to_string(),
                }),
                http::StatusCode::INTERNAL_SERVER_ERROR,
            ));
        }
    };

    // Generate a reset token
    let exp = Utc::now().timestamp() + Duration::minutes(15).num_seconds();
    let exp_str = exp.to_string();
    let uid = user.uid.to_string();

    // Generate a reset token and save it to the database
    let mut claims: BTreeMap<&str, &str> = BTreeMap::new();
	claims.insert("iss", "TurboCore");
	claims.insert("uid", &uid);
	claims.insert("exp", &exp_str);
	claims.insert("type", "password_reset");

    let reset_token = claims.sign_with_key(&data.config.secret_key).unwrap();

    let action_url = format!("{}?token={}", body.reset_url, reset_token);

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

    // Send the reset email
    forgot_password::send(EmailParams {
		name: body.email.to_owned(),
		action_url,
		subject: email_config.forgot_password_subject,
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
