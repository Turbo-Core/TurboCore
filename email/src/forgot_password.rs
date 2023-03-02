use lettre::message::header::ContentType;
use lettre::message::{MultiPart, SinglePart};
use lettre::AsyncTransport;
use lettre::Message;
use log::error;
use sailfish::TemplateOnce;

use crate::EmailParams;

#[derive(TemplateOnce)]
#[template(path = "forgot_password.stpl")]
struct PasswordTemplateHtml {
	name: String,
	action_url: String,
	operating_system: String,
	device: String,
}

#[derive(TemplateOnce)]
#[template(path = "forgot_password.txt")]
struct PasswordTemplateTxt {
	name: String,
	action_url: String,
}

pub async fn send(params: EmailParams<'_>) {
	let html = PasswordTemplateHtml {
		action_url: params.action_url.clone(),
		name: params.name.clone(),
		operating_system: params.os,
		device: params.device,
	}
	.render_once()
	.unwrap();

	let txt = PasswordTemplateTxt {
		action_url: params.action_url,
		name: params.name,
	}
	.render_once()
	.unwrap();

	let email = Message::builder()
		.from(params.from.parse().unwrap())
		.reply_to(params.reply_to.parse().unwrap())
		.to(params.to.parse().unwrap())
		.subject(params.subject)
		.multipart(
			MultiPart::alternative()
				.singlepart(
					SinglePart::builder()
						.header(ContentType::TEXT_PLAIN)
						.body(txt),
				)
				.singlepart(
					SinglePart::builder()
						.header(ContentType::TEXT_HTML)
						.body(html),
				),
		);

	let email = match email {
		Ok(email) => email,
		Err(err) => {
			error!("Failed to build email: {err}");
			return;
		}
	};

	match params.mailer.send(email).await {
		Ok(_) => (),
		Err(err) => error!("Failed to send email: {err}"),
	}
}
