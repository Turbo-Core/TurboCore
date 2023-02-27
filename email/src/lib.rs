use lettre::{AsyncSmtpTransport, Tokio1Executor};

pub mod forgot_password;
pub mod magic;
pub mod manual;
pub mod verification;

pub struct EmailParams<'a> {
	pub name: String,
	pub action_url: String,
	pub subject: String,
	pub from: String,
	pub to: String,
	pub reply_to: String,
	pub os: String,
	pub device: String,
	pub mailer: &'a AsyncSmtpTransport<Tokio1Executor>,
}
