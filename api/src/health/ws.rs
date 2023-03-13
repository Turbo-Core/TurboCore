// Adapted from: https://github.com/actix/examples/blob/6571dfef82248a7172729e280bf4150aa12a8d49/websockets/echo-actorless/src/handler.rs
use std::{
	collections::BTreeMap,
	time::{Duration, Instant},
};

use crate::{health::sysinfo::sysinfo as sysinfo_fn, AppState};
use actix_web::{web, Error, HttpRequest, HttpResponse};
use actix_ws::{Message, Session};
use chrono::Utc;
use futures_util::{
	future::{self, Either},
	StreamExt as _,
};
use jwt::VerifyWithKey;
use log::debug;
use sysinfo::{System, SystemExt};
use tokio::{pin, task::spawn_local, time::interval};

/// How often heartbeat pings are sent.
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);

/// How long before lack of client response causes a timeout.
const CLIENT_TIMEOUT: Duration = Duration::from_secs(10);

/// Echo text & binary messages received from the client, respond to ping messages, and monitor
/// connection health to detect network issues and free up resources.
pub async fn sysinfo(
	mut session: actix_ws::Session,
	mut msg_stream: actix_ws::MessageStream,
	mut data: WSData,
	state: web::Data<AppState>,
) {
	debug!("sysinfo() called");
	let mut last_heartbeat = Instant::now();
	let mut interval = interval(HEARTBEAT_INTERVAL);

	let reason = loop {
		// create "next client timeout check" future
		let tick = interval.tick();
		// required for select()
		pin!(tick);

		// waits for either `msg_stream` to receive a message from the client or the heartbeat
		// interval timer to tick, yielding the value of whichever one is ready first
		match future::select(msg_stream.next(), tick).await {
			// received message from WebSocket client
			Either::Left((Some(Ok(msg)), _)) => {
				log::debug!("msg: {msg:?}");
				match msg {
					Message::Text(text) => {
						let text = text.to_string();
						let text = text.as_str();
						if handle_command(&mut data, &mut session, text, &state.config.secret_key)
							.await
							.is_err()
						{
							break None;
						}
					}

					Message::Binary(_) => {
						session.text("no support for binary frames").await.unwrap();
					}

					Message::Close(reason) => {
						break reason;
					}

					Message::Ping(bytes) => {
						last_heartbeat = Instant::now();
						let _ = session.pong(&bytes).await;
					}

					Message::Pong(_) => {
						last_heartbeat = Instant::now();
					}

					Message::Continuation(_) => {
						log::warn!("no support for continuation frames");
					}

					// no-op; ignore
					Message::Nop => {}
				};
			}

			// client WebSocket stream error
			Either::Left((Some(Err(err)), _)) => {
				log::error!("{}", err);
				break None;
			}

			// client WebSocket stream ended
			Either::Left((None, _)) => break None,

			// heartbeat interval ticked
			Either::Right((_inst, _)) => {
				// if no heartbeat ping/pong received recently, close the connection
				if Instant::now().duration_since(last_heartbeat) > CLIENT_TIMEOUT {
					break None;
				}

				// send heartbeat ping
				let _ = session.ping(b"").await;
			}
		}
	};

	// attempt to close connection gracefully
	let _ = session.close(reason).await;
}

pub async fn sysinfo_ws(
	req: HttpRequest,
	stream: web::Payload,
	sys_data: web::Data<WSData>,
	state: web::Data<AppState>,
) -> Result<HttpResponse, Error> {
	let (res, session, msg_stream) = actix_ws::handle(&req, stream)?;

	// spawn websocket handler (and don't await it) so that the response is returned immediately
	spawn_local(sysinfo(session, msg_stream, (**sys_data).clone(), state));

	Ok(res)
}

async fn handle_command(
	data: &mut WSData,
	session: &mut Session,
	msg: &str,
	secret_key: &hmac::Hmac<sha2::Sha256>,
) -> Result<(), String> {
	let mut cmds = msg.split_whitespace();
	let cmd = cmds.next();

	if let Some(cmd) = cmd {
		if cmd == "auth" {
			let key = cmds.next();
			if let Some(key) = key {
				let claims: BTreeMap<String, String> = match key.verify_with_key(secret_key) {
					Ok(claims) => claims,
					Err(_) => {
						session.text("invalid key").await.unwrap();
						return Err("invalid key".to_string());
					}
				};
				// Confirm AT and not expired
				if claims["type"] == "at" && Utc::now().timestamp() < claims["exp"].parse().unwrap() {
					data.auth = true;
					session.text("ok").await.unwrap();
					return Ok(());
				}
				session.text("not authorized").await.unwrap();
				return Err("not authorized".to_string());
			}
			session.text("not authorized").await.unwrap();
			return Err("not authorized".to_string());
		}
	}

	match msg {
		"sysinfo" => {
			if !data.auth {
				session.text("not authorized").await.unwrap();
				return Err("not authorized".to_string());
			}
			let msg = sysinfo_fn(&mut data.sys);
			session.text(msg).await.unwrap();
			Ok(())
		}
		_ => {
			session.text("unknown command").await.unwrap();
			Ok(())
		}
	}
}

pub struct WSData {
	pub sys: System,
	pub auth: bool,
}

impl Clone for WSData {
	fn clone(&self) -> Self {
		Self {
			sys: System::new_all(),
			auth: self.auth,
		}
	}
}
