use crate::{
	auth::{api_error, util::get_at_and_rt, ApiResponse},
	AppState,
};
use actix_web::{
	http, post,
	web::{Data, Json},
	Responder,
};
use argon2;
use entity::admins;
use log::error;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use serde::Deserialize;


#[derive(Deserialize)]
pub struct LoginBody {
	email: String,
	password: String,
}

#[post("/api/admin/login")]
pub async fn handler(data: Data<AppState>, body: Json<LoginBody>) -> impl Responder {
    let res = admins::Entity::find()
		.filter(admins::Column::Email.eq(&body.email))
		.one(&data.connection)
		.await;

    match res {
        Ok(opt) => {
            match opt {
                Some(admin) => {
					if !argon2::verify_encoded(&admin.password, body.password.as_bytes()).unwrap() {
						return (
							Json(api_error(
								"The email or password is invalid".to_string(),
								"INVALID_CREDENTIALS".to_string(),
							)),
							http::StatusCode::UNAUTHORIZED,
						);
					}
					let uid_str = &admin.uid.to_string();
					let (at, rt, exp) =
						get_at_and_rt(&data.connection, uid_str, &data.config.secret_key, true).await;
					(
						Json(ApiResponse::LoginResponse {
							uid: uid_str.to_string(),
							token: at,
							expiry: exp,
							refresh_token: rt,
							email_verified: admin.email_verified,
							metadata: admin.metadata.clone().unwrap_or("".to_string()),
						}),
						http::StatusCode::OK,
					)
                }, 
                None => (
					Json(api_error(
						"The email or password is invalid".to_string(),
						"INVALID_CREDENTIALS".to_string(),
					)),
					http::StatusCode::UNAUTHORIZED,
				)
            }
        },
        Err(e) => {
            error!("An error occurred when finding user. Error: {}", e.to_string());
			(
				Json(api_error(
					"An internal server error occurred.".to_string(),
					"INTERNAL_SERVER_ERROR".to_string(),
				)),
				http::StatusCode::INTERNAL_SERVER_ERROR,
			)
        }
    }

}