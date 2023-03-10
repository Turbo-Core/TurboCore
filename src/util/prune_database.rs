use chrono::{Duration, Utc};
use entity::refresh_tokens;
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};

pub async fn run(database_connection: DatabaseConnection) {
	// We will delete all refresh tokens that expired more than 21 days ago
	let expiry_date = Utc::now() - Duration::days(21);
	let _res = refresh_tokens::Entity::delete_many()
		.filter(refresh_tokens::Column::Expiry.lte(expiry_date))
		.exec(&database_connection)
		.await;
}
