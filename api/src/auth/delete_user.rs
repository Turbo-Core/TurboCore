use crate::{
    auth::util::{self, HeaderResult},
    AppState,
};
use actix_web::{
    delete, http,
    web::{Data, Json},
    Either, HttpResponse,
};
use entity::{refresh_tokens, users};
use log::error;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};

use super::ApiResponse;

#[delete("/api/auth/user")]
pub async fn handler(
    request: actix_web::HttpRequest,
    data: Data<AppState>,
) -> DeleteUserResponse<'static> {
    let header_map = request.headers();
    let authorization = header_map.get("Authorization");

    let uid = match util::verify_header(authorization, &data.config.secret_key) {
        HeaderResult::Error(r, s) => {
            return Either::Left((r, s));
        }
        HeaderResult::Uid(uid) => uid,
    };

    // Delete the user
    match users::Entity::delete_by_id(uid)
        .exec(&data.connection)
        .await
    {
        Ok(_) => (),
        Err(e) => error!(
            "Failed to delete user {}. Error: {}",
            uid.to_string(),
            e.to_string()
        ),
    }

    // Delete the refresh tokens
    match refresh_tokens::Entity::delete_many()
        .filter(refresh_tokens::Column::Uid.eq(uid))
        .exec(&data.connection)
        .await
    {
        Ok(_) => (),
        Err(e) => error!(
            "Failed to delete refresh tokens for {}. Error: {}",
            uid.to_string(),
            e.to_string()
        ),
    }

    Either::Right(HttpResponse::Ok().finish())
}

type DeleteUserResponse<'a> = Either<(Json<ApiResponse>, http::StatusCode), HttpResponse>;
