use crate::error::Error;
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHasher};
use serde::{Deserialize, Serialize};
use tokio_postgres::GenericClient;

#[derive(Deserialize, Serialize)]
#[serde(transparent)]
pub struct User {
    id: i32,
}

pub struct UserStore<'d, D: GenericClient> {
    database: &'d D,
}

impl<'d, D: GenericClient> UserStore<'d, D> {
    pub fn new(database: &'d D) -> Self {
        Self { database }
    }

    pub async fn insert(&self, username: &str, password: &str) -> Result<User, Error> {
        let argon2 = Argon2::default();
        let salt = SaltString::generate(OsRng);
        let hash = argon2.hash_password(password.as_bytes(), &salt).unwrap();
        let row = self
            .database
            .query_one(
                "INSERT INTO users (username, password_phc) VALUES ($1, $2) RETURNING id;",
                &[&username, &hash.to_string()],
            )
            .await?;
        let id = row.get(0);
        Ok(User { id })
    }
}

impl slog::KV for User {
    fn serialize(
        &self,
        record: &slog::Record,
        serializer: &mut dyn slog::Serializer,
    ) -> slog::Result {
        slog::Value::serialize(self, record, "user", serializer)
    }
}

impl slog::Value for User {
    fn serialize(
        &self,
        _record: &slog::Record,
        key: slog::Key,
        serializer: &mut dyn slog::Serializer,
    ) -> slog::Result {
        serializer.emit_i32(key, self.id)
    }
}
