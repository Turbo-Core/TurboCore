use actix_web::web;

pub mod sysinfo;
pub mod ws;
pub mod ping;

pub fn add_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(crate::health::ping::handler);
}