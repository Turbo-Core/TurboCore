// Adapted from: https://github.com/actix/examples/blob/6571dfef82248a7172729e280bf4150aa12a8d49/websockets/echo-actorless/src/handler.rs
use std::time::{Duration, Instant};

use actix_web::{web, Error, HttpRequest, HttpResponse, Responder};
use actix_ws::Message;
use futures_util::{
	future::{self, Either},
	StreamExt as _,
};
use log::debug;
use tokio::{pin, task::spawn_local, time::interval};
use sysinfo::{System, SystemExt};
use crate::{health::sysinfo::sysinfo as sysinfo_fn, AppState, auth::util::{verify_header, HeaderResult}};

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
					Message::Text(text) => match text.to_string().as_str() {
						"sysinfo" => {
							let msg = sysinfo_fn(&mut data.sys);
                            session.text(msg).await.unwrap();
						}
						_ => {
							session.text("unknown command").await.unwrap();
						}
					},

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
	state: web::Data<AppState>
) -> Result<actix_web::Either<HttpResponse, impl Responder>, Error> {

	let header_map = req.headers();

	// Verify that the request is authorized
	let _uid = match verify_header(header_map.get("Authorization"), &state.config.secret_key) {
		HeaderResult::Error(r, s) => {
			return Ok(actix_web::Either::Right((r, s)));
		}
		HeaderResult::Uid(uid) => uid
	};

	let (res, session, msg_stream) = actix_ws::handle(&req, stream)?;

	// spawn websocket handler (and don't await it) so that the response is returned immediately
	spawn_local(sysinfo(session, msg_stream, (**sys_data).clone()));

	Ok(actix_web::Either::Left(res))
}

pub struct WSData {
	pub sys: System,
}

impl Clone for WSData {
	fn clone(&self) -> Self {
		Self {
			sys: System::new_all(),
		}
	}
}
