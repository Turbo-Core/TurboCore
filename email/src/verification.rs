use lettre::message::header::ContentType;
use lettre::message::{MultiPart, SinglePart};
use lettre::AsyncTransport;
use lettre::Message;
use sailfish::TemplateOnce;

use crate::EmailParams;

#[derive(TemplateOnce)]
#[template(path = "verification.stpl")]
struct VerificationTemplateHtml {
	name: String,
	action_url: String,
}

#[derive(TemplateOnce)]
#[template(path = "verification.txt")]
struct VerificationTemplateTxt {
	name: String,
	action_url: String,
}

pub async fn send(params: EmailParams<'_>) {
	let html = VerificationTemplateHtml {
		action_url: params.action_url.clone(),
		name: params.name.clone(),
	}
	.render_once()
	.unwrap();

	let txt = VerificationTemplateTxt {
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
						.header(ContentType::TEXT_HTML)
						.body(html),
				)
				.singlepart(
					SinglePart::builder()
						.header(ContentType::TEXT_PLAIN)
						.body(txt),
				),
		)
		.unwrap();

	match params.mailer.send(email).await {
		Ok(a) => (),
		Err(err) => println!("{err}"),
	}
	// println!("{html}");
}
