use chrono::{NaiveDateTime, Utc};
use entity::refresh_tokens;
use jwt::SignWithKey;
use rand::{distributions::Alphanumeric, thread_rng, Rng};
use sea_orm::{DatabaseConnection, EntityTrait, Set};
use std::collections::BTreeMap;

/// Generates a JWT access token and a JWT refresh token, and expiry for the AT.
/// Returns the value as a tuple and store the refresh token in the database
pub async fn get_at_and_rt(
    connection: &DatabaseConnection,
    uid: &String,
    key: &hmac::Hmac<sha2::Sha256>,
) -> (String, String, i64) {
    let mut token = BTreeMap::new();
    let mut refresh_token = BTreeMap::new();

    // TODO: make exp configurable
    // The RFC protocol allows for some lee way ("up to a few minutes") in exp, hence +15 seconds
    let short_exp = Utc::now().timestamp() + 15 * 60 + 15;
    let short_exp_str = short_exp.to_string();
    let long_exp = Utc::now().timestamp() + 60 * 60 * 24 * 7;
    let long_exp_str = long_exp.to_string();

    // RT is used as a primary key in db and must be unique. Two tokens (with same uid) generated in the same second will
    // be the same, so we add some randomness to make the possibility of a collision during the same second 1 / 62^5
    let rand_val: String = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(5)
        .map(char::from)
        .collect();
    refresh_token.insert("iss", "TurboCore");
    refresh_token.insert("exp", &long_exp_str);
    refresh_token.insert("uid", uid);
    refresh_token.insert("rand", &rand_val);

    token.insert("iss", "TurboCore");
    token.insert("exp", &short_exp_str);
    token.insert("uid", uid);

    let rt = refresh_token.sign_with_key(key).unwrap();

    // Add new one
    refresh_tokens::Entity::insert(refresh_tokens::ActiveModel {
        uid: Set(uid.to_string()),
        refresh_token: Set(rt.to_owned()),
        expiry: Set(NaiveDateTime::from_timestamp_opt(long_exp, 0).unwrap()),
        used: Set(false),
    })
    .exec(connection)
    .await
    .unwrap();

    (token.sign_with_key(key).unwrap(), rt, short_exp)
}
