#![allow(non_snake_case)] // Let's be honest, camelCase is better. But going forward, I will try to use snake_case

mod util;

// Internal
use api::{auth::{self}, AppState};
use uaparser::UserAgentParser;
use util::{load_config::load_config, prune_database};
use tokio::{spawn, time::{sleep, Duration}};

// Actix
use actix_web::{
	http::{header::SERVER, self, StatusCode},
	middleware::{self, Logger},
	web::{self, Data, BytesMut},
	App, HttpServer, ResponseError, HttpResponse, body::BoxBody,
};

// Sea-ORM
use migration::{Migrator, MigratorTrait};

use clokwerk::{AsyncScheduler, TimeUnits};

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

	let connection2 = sea_orm::Database::connect(config.connection_url.to_owned())
		.await
		.unwrap();

	// Build the scheduler and add a job to it
	let mut scheduler = AsyncScheduler::new();
	scheduler.every(15.minutes()).run(move || prune_database::run(connection2.to_owned()));

	// Move the scheduler into a new thread
	spawn (async move {
		loop {
			scheduler.run_pending().await;
			sleep(Duration::from_secs(10)).await;
			// The sleep duration is arbitrary, but it should be less than the interval
			// Since pruning the DB isn't a critical task, the sleep duration can be longer
		}
	});

	HttpServer::new(move || {
		let ua_parser = UserAgentParser::from_yaml("regexes.yaml").unwrap();
		
		let json_cfg = web::JsonConfig::default()
		.error_handler(|err, _req| {
			let err = format!("Error parsing JSON: {err}");
			log::warn!("{err}");
			JsonError {
				message: err,
				error_code: "JSON_ERROR".to_string(),
			}.into()
		});

		App::new()
			.app_data(Data::new(AppState {
				connection: connection.to_owned(),
				config: config.to_owned(),
				ua_parser,
			}))
			.app_data(json_cfg)
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
		.service(auth::delete_user::handler)
		.service(auth::change_password::handler)
		.service(auth::email_verify::send_handler)
		.service(auth::email_verify::receive_handler)
		.service(auth::magic_link::get_handler)
		.service(auth::magic_link::post_handler)
		.service(auth::reset_password::handler);
}

#[derive(Debug)]
struct JsonError {
	message: String,
	error_code: String,
}

impl std::fmt::Display for JsonError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("JsonError")
			.field("message", &self.message)
			.field("error_code", &self.error_code)
			.finish()
	}
}

impl ResponseError for JsonError {
	fn status_code(&self) -> StatusCode {
		StatusCode::BAD_REQUEST
	}

	fn error_response(&self) -> HttpResponse<BoxBody> {
        let mut res = HttpResponse::new(self.status_code());

		res.headers_mut().insert(
			http::header::CONTENT_TYPE,
			http::header::HeaderValue::from_static("application/json"),
		);

		let box_body = BoxBody::new(BytesMut::from(format!(
			"{{\"message\": \"{}\", \"error_code\": \"{}\"}}",
			self.message, self.error_code
		).as_bytes()));

		res.set_body(box_body)
    }
}