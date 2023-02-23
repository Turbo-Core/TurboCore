use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
	async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
		manager
			.create_table(
				Table::create()
					.table(User::Table)
					.if_not_exists()
					.col(ColumnDef::new(User::Uid).uuid().not_null().primary_key())
					.col(ColumnDef::new(User::Email).string().not_null())
					.col(ColumnDef::new(User::Password).string().not_null())
					.col(ColumnDef::new(User::CreatedAt).date_time().not_null())
					.col(ColumnDef::new(User::UpdatedAt).date_time().not_null())
					.col(ColumnDef::new(User::LastLogin).date_time())
					.col(ColumnDef::new(User::Active).boolean().not_null())
					.col(ColumnDef::new(User::Metadata).string())
					.col(ColumnDef::new(User::EmailVerified).boolean().not_null())
					.to_owned(),
			)
			.await?;
		manager
			.create_table(
				Table::create()
					.table(RefreshTokenEntry::Table)
					.if_not_exists()
					.col(ColumnDef::new(RefreshTokenEntry::Uid).uuid().not_null())
					.col(
						ColumnDef::new(RefreshTokenEntry::RefreshToken)
							.string()
							.not_null()
							.primary_key(),
					)
					.col(
						ColumnDef::new(RefreshTokenEntry::Expiry)
							.date_time()
							.not_null(),
					)
					.col(ColumnDef::new(RefreshTokenEntry::Used).boolean().not_null())
					.to_owned(),
			)
			.await?;
		manager
			.create_index(
				sea_query::Index::create()
					.name("users_email")
					.table(User::Table)
					.col(User::Email)
					.unique()
					.to_owned(),
			)
			.await?;
		manager
			.create_index(
				sea_query::Index::create()
					.name("users_uid")
					.table(User::Table)
					.col(User::Uid)
					.to_owned(),
			)
			.await?;
		manager
			.create_index(
				sea_query::Index::create()
					.name("refresh_tokens_index")
					.table(RefreshTokenEntry::Table)
					.col(RefreshTokenEntry::RefreshToken)
					.to_owned(),
			)
			.await
	}
	async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
		manager
			.drop_table(Table::drop().table(User::Table).to_owned())
			.await?;
		manager
			.drop_table(Table::drop().table(RefreshTokenEntry::Table).to_owned())
			.await
	}
}

/// Learn more at https://docs.rs/sea-query#iden
#[derive(Iden)]
enum User {
	#[iden = "users"]
	Table,
	Uid,
	Email,
	Password,
	CreatedAt,
	UpdatedAt,
	LastLogin,
	Active,
	Metadata,
	EmailVerified,
}

#[derive(Iden)]
enum RefreshTokenEntry {
	#[iden = "refresh_tokens"]
	Table,
	Uid,
	RefreshToken,
	Expiry,
	Used,
}
