use actix_web::web;

pub mod create_admin;
pub mod login;


pub fn add_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(crate::admin::create_admin::handler)
        .service(crate::admin::login::handler);
}