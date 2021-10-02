use crate::error::Error;
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use serde::{Deserialize, Serialize};
use tokio_postgres::GenericClient;

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(transparent)]
pub struct User {
    pub id: i32,
}

pub struct UserStore<'d, D: GenericClient> {
    argon2: Argon2<'static>,
    database: &'d D,
}

impl<'d, D: GenericClient> UserStore<'d, D> {
    pub fn new(database: &'d D) -> Self {
        Self {
            argon2: Argon2::default(),
            database,
        }
    }

    pub async fn get_and_verify(&self, username: &str, password: &str) -> Result<User, Error> {
        let row = self
            .database
            .query_one(
                "SELECT id, password_phc FROM users WHERE username = $1",
                &[&username],
            )
            .await?;
        let id: i32 = row.get(0);
        let password_phc: &str = row.get(1);
        let password_phc = PasswordHash::new(password_phc).unwrap();
        self.argon2
            .verify_password(password.as_bytes(), &password_phc)
            .unwrap();
        Ok(User { id })
    }

    pub async fn insert(&self, username: &str, password: &str) -> Result<User, Error> {
        let salt = SaltString::generate(OsRng);
        let hash = self
            .argon2
            .hash_password(password.as_bytes(), &salt)
            .unwrap();
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
