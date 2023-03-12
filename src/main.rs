#![allow(non_snake_case)] // Let's be honest, camelCase is better. But going forward, I will try to use snake_case
mod util;

// Internal
use actix_web::{
	http::header::SERVER,
	middleware::{self, Logger},
	web::{self, Data},
	App, HttpServer,
};
use api::{AppState, JsonError, health::ws::WSData};
use clokwerk::{AsyncScheduler, TimeUnits};
use migration::{Migrator, MigratorTrait};
use sysinfo::{System, SystemExt};
use tokio::{
	spawn,
	time::{sleep, Duration},
};
use uaparser::UserAgentParser;
use util::{load_config::load_config, prune_database};

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
	scheduler
		.every(15.minutes())
		.run(move || prune_database::run(connection2.to_owned()));

	// Move the scheduler into a new thread
	spawn(async move {
		loop {
			scheduler.run_pending().await;
			sleep(Duration::from_secs(10)).await;
			// The sleep duration is arbitrary, but it should be less than the interval
			// Since pruning the DB isn't a critical task, the sleep duration can be longer
		}
	});

	HttpServer::new(move || {
		let ua_parser = UserAgentParser::from_yaml("regexes.yaml").unwrap();

		let json_cfg = web::JsonConfig::default().error_handler(|err, _req| {
			let err = format!("Error parsing JSON: {err}");
			log::warn!("{err}");
			JsonError {
				message: err,
				error_code: "JSON_ERROR".to_string(),
			}
			.into()
		});

		let ws_data = Data::new(WSData {
			sys: System::new_all(),
		});

		App::new()
			.app_data(Data::new(AppState {
				connection: connection.to_owned(),
				config: config.to_owned(),
				ua_parser,
			}))
			.service(web::resource("/api/health/ws").route(web::get().to(api::health::ws::sysinfo_ws)))
			.app_data(json_cfg)
			.app_data(ws_data)
			.wrap(middleware::DefaultHeaders::new().add((SERVER, "TurboCore")))
			.wrap(Logger::default())
			.configure(api::auth::add_routes)
	})
	.bind(bind_addr)?
	.run()
	.await
}
