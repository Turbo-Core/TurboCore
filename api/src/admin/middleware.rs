use std::{collections::BTreeMap, rc::Rc, str::FromStr};

use actix_web::{
	body::{EitherBody, MessageBody},
	dev::{Service, ServiceRequest, ServiceResponse, Transform},
	error::ErrorUnauthorized,
	Error,
};
use futures::{
	executor::block_on,
	future::{ok, LocalBoxFuture},
	FutureExt,
};
use futures_util::future::Ready;
use hmac::Hmac;
use jwt::VerifyWithKey;
use sea_orm::EntityTrait;
use sha2::Sha256;
use uuid::Uuid;

pub struct AdminMiddlewareFactory {
	key: Hmac<Sha256>,
	db_conn: sea_orm::DatabaseConnection,
}

impl AdminMiddlewareFactory {
	pub fn new(key: Hmac<Sha256>, db_conn: sea_orm::DatabaseConnection) -> Self {
		Self { key, db_conn }
	}
}

impl<S, B> Transform<S, ServiceRequest> for AdminMiddlewareFactory
where
	S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
	S::Future: 'static,
	B: MessageBody + 'static,
{
	type Response = ServiceResponse<EitherBody<B>>;
	type Error = Error;
	type Transform = AdminMiddleware<S>;
	type InitError = ();
	type Future = Ready<Result<Self::Transform, Self::InitError>>;

	fn new_transform(&self, service: S) -> Self::Future {
		ok(AdminMiddleware {
			service: Rc::new(service),
			key: self.key.clone(),
			db_conn: self.db_conn.clone(),
		})
	}
}

pub struct AdminMiddleware<S> {
	service: Rc<S>,
	key: Hmac<Sha256>,
	db_conn: sea_orm::DatabaseConnection,
}

impl<S, B> Service<ServiceRequest> for AdminMiddleware<S>
where
	S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
	S::Future: 'static,
	B: MessageBody + 'static,
{
	type Response = ServiceResponse<EitherBody<B>>;
	type Error = Error;
	type Future = LocalBoxFuture<'static, Result<ServiceResponse<EitherBody<B>>, Error>>;

	actix_service::forward_ready!(service);

	fn call(&self, req: ServiceRequest) -> Self::Future {
		// For brevity
		macro_rules! unauthorizedBoxPin {
			() => {
				Box::pin(ok(req
					.error_response(ErrorUnauthorized("Invalid authorization header"))
					.map_into_right_body()))
			};
		}
		if req.path().starts_with("/api/admin") {
			let token = match req.headers().get("Authorization") {
				Some(token) => match token.to_str() {
					Ok(token) => token,
					Err(_) => {
						return unauthorizedBoxPin!();
					}
				},
				None => {
					return Box::pin(ok(req
						.error_response(ErrorUnauthorized("Missing authorization header"))
						.map_into_right_body()));
				}
			};

			let parts: Vec<&str> = token.split_whitespace().collect();

			if parts[0] == "bearer" || parts[0] == "Bearer" {
				let token = match parts.get(1) {
					Some(token) => *token,
					None => {
						return unauthorizedBoxPin!();
					}
				};

				let claims: BTreeMap<String, String> = match token.verify_with_key(&self.key) {
					Ok(claims) => claims,
					Err(_) => {
						return unauthorizedBoxPin!();
					}
				};
				if claims["type"] != "at" {
					return unauthorizedBoxPin!();
				}
				match claims.get("role") {
					Some(role) => {
						if role != "admin" {
							return unauthorizedBoxPin!();
						}
					}
					None => {
						return unauthorizedBoxPin!();
					}
				};
			} else if parts[0] == "token" || parts[0] == "Token" {
				let token = match parts.get(1) {
					Some(token) => match Uuid::from_str(token) {
						Ok(token) => token,
						Err(_) => {
							return unauthorizedBoxPin!();
						}
					},
					None => {
						return unauthorizedBoxPin!();
					}
				};
			} else {
				return unauthorizedBoxPin!();
			}
		}

		let service = Rc::clone(&self.service);
		async move { service.call(req).await.map(|res| res.map_into_left_body()) }.boxed_local()
	}
}
