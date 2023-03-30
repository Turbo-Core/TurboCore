// Simply responds with a 200 OK and "pong" as the body

use actix_web::{route, HttpResponse, Responder};

#[route("/api/health/ping", method = "GET", method = "POST")]
pub async fn handler() -> impl Responder {
	HttpResponse::Ok().body("pong")
}
