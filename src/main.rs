#![allow(non_snake_case)] // Let's be honest, camelCase is better. But going forward, I will try to use snake_case

mod api;
mod util;

use api::auth::{
    login
};
use actix_web::{HttpServer, App, middleware::{Logger, self}, http::header::SERVER};
use util::load_config::{
    load_config
};

#[actix_web::main]
async fn main() -> std::io::Result<()> {

    let config = load_config();

    std::env::set_var("RUST_LOG", config.debug_level);
    env_logger::init();

    HttpServer::new(move || {
        App::new()
            .wrap(middleware::DefaultHeaders::new()
                .add((SERVER, "TrueCore")))
            .wrap(Logger::default())
            .service(login)
    })
    .bind("0.0.0.0:8080")?
    .run()
    .await
}