use crate::{
	auth::{
        util::get_at_and_rt,
		ApiResponse,
	},
	AppState,
};
use actix_web::{
	get, http, post,
	web::{Data, Json, Path, Query},
	Either, HttpResponse,
};

use email::{verification, EmailParams};
use entity::users;
use log::error;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};
use uuid::Uuid;

#[derive(serde::Deserialize)]
pub struct MagicBody {
	pub next_url: String,
	pub email: String,
	pub sign_up: bool,
}

#[post("/api/auth/user/magic-link")]
pub async fn post_handler(
	data: Data<AppState>,
	body: Json<MagicBody>,
) -> Either<(Json<ApiResponse>, http::StatusCode), HttpResponse> {
	if data.config.mailer.is_none() || data.config.email.is_none() {
		return Either::Left((
			Json(ApiResponse::ApiError {
				message: "The server is not configured to send emails.".to_string(),
				error_code: "EMAIL_NOT_CONFIGURED".to_string(),
			}),
			http::StatusCode::BAD_REQUEST,
		));
	}

	let user = match users::Entity::find()
		.filter(users::Column::Email.eq(body.email.to_owned()))
		.one(&data.connection)
		.await
	{
		Ok(user) => match user {
			Some(user) => {
				if body.sign_up {
					return Either::Left((
						Json(ApiResponse::ApiError {
							message: "The user already exists.".to_string(),
							error_code: "USER_ALREADY_EXISTS".to_string(),
						}),
						http::StatusCode::BAD_REQUEST,
					));
				}
				user
			}
			None => {
				if !body.sign_up {
					return Either::Left((
						Json(ApiResponse::ApiError {
							message: "The user does not exist.".to_string(),
							error_code: "USER_DOES_NOT_EXIST".to_string(),
						}),
						http::StatusCode::BAD_REQUEST,
					));
				}
                let uid = Uuid::new_v4();
				let new_user = users::ActiveModel {
                    uid: Set(uid),
                    password: Set("0".to_string()),
					email: Set(body.email.to_owned()),
					..Default::default()
				};
                let new_user = new_user.insert(&data.connection).await;
                match new_user {
                    Ok(user) => user,
                    Err(e) => {
                        error!("Unable to create user. Error: {}", e.to_string());
                        return Either::Left((
                            Json(ApiResponse::ApiError {
                                message: "Internal Server Error".to_string(),
                                error_code: "INTERNAL_SERVER_ERROR".to_string(),
                            }),
                            http::StatusCode::INTERNAL_SERVER_ERROR,
                        ));
                    }
                }
			}
		},
		Err(e) => {
			error!("Unable to find user. Error: {}", e.to_string());
			return Either::Left((
				Json(ApiResponse::ApiError {
					message: "Internal Server Error".to_string(),
					error_code: "INTERNAL_SERVER_ERROR".to_string(),
				}),
				http::StatusCode::INTERNAL_SERVER_ERROR,
			));
		}
	};

    let action_url = format!(
        "{}/api/auth/user/magic-link/{}?next={}",
        data.config.base_url, user.uid, body.next_url
    );

	let mailer = data.config.mailer.as_ref().unwrap();

	let email_config = data.config.email.to_owned().unwrap();

	verification::send(EmailParams {
		name: user.email.to_owned(),
		action_url,
		subject: email_config.confirmation_subject,
		from: email_config.from,
		to: user.email,
		reply_to: email_config.reply_to,
		mailer,
	})
	.await;

	Either::Right(HttpResponse::Ok().finish())
}

#[derive(serde::Deserialize)]
pub struct NextUrl {
    pub next_url: String,
}


#[get("/api/auth/user/magic-link/{uid}")]
pub async fn get_handler(data: Data<AppState>, path: Path<String>, next: Query<NextUrl>) -> HttpResponse {
    let uid = match Uuid::parse_str(&path) {
        Ok(uid) => uid,
        Err(_) => {
            return HttpResponse::BadRequest().json(ApiResponse::ApiError {
                message: "Invalid UID".to_string(),
                error_code: "INVALID_UID".to_string(),
            })
        }
    };

    let user = match users::Entity::find()
        .filter(users::Column::Uid.eq(uid))
        .one(&data.connection)
        .await
    {
        Ok(user) => match user {
            Some(user) => user,
            None => {
                return HttpResponse::BadRequest().json(ApiResponse::ApiError {
                    message: "The user does not exist.".to_string(),
                    error_code: "USER_DOES_NOT_EXIST".to_string(),
                })
            }
        },
        Err(e) => {
            error!("Unable to find user. Error: {}", e.to_string());
            return HttpResponse::InternalServerError().json(ApiResponse::ApiError {
                message: "Internal Server Error".to_string(),
                error_code: "INTERNAL_SERVER_ERROR".to_string(),
            });
        }
    };

    let (at, rt, exp) = get_at_and_rt(&data.connection, &user.uid.to_string(), &data.config.secret_key).await;

    let redirect_url = format!(
        "{}?at={}&rt={}&exp={}",
        next.next_url, at, rt, exp
    );

    HttpResponse::Found()
        .append_header(("Location", redirect_url))
        .finish()
}