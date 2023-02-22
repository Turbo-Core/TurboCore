#![allow(non_snake_case)] // Let's be honest, camelCase is better. But going forward, I will try to use snake_case

mod util;

// Internal
use api::{auth, AppState};
use util::load_config::load_config;

// Actix
use actix_web::{
    http::header::SERVER,
    middleware::{self, Logger},
    web::{self, Data},
    App, HttpServer,
};

// Sea-ORM
use migration::{Migrator, MigratorTrait};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let config = load_config();

    let bind_addr = config.bind_addr.to_owned();

    std::env::set_var("RUST_LOG", &config.debug_level);
    env_logger::init();

    let connection = sea_orm::Database::connect(config.connection_url.to_owned())
        .await
        .unwrap();

    Migrator::up(&connection, None).await.unwrap();

    HttpServer::new(move || {
        App::new()
            .app_data(Data::new(AppState {
                connection: connection.to_owned(),
                config: config.to_owned(),
            }))
            .wrap(middleware::DefaultHeaders::new().add((SERVER, "TurboCore")))
            .wrap(Logger::default())
            .configure(add_routes)
    })
    .bind(bind_addr)?
    .run()
    .await
}

fn add_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(auth::signup::handler)
        .service(auth::login::handler)
        .service(auth::refresh::handler)
        .service(auth::get_user::handler)
        .service(auth::delete_user::handler);
}
