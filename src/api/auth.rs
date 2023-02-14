use actix_web::web::Json;
use actix_web::get;

// TODO: Implement auth
#[get("/")]
pub async fn login() -> Json<String> {
    Json("Hello world".to_string())
}