use crate::error::Error;
use crate::user::User;
use cookie::{Cookie, SameSite};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::convert::TryInto;
use std::time::Duration;

#[derive(Deserialize, Serialize)]
#[serde(transparent)]
pub struct Session {
    user: User,
}

const EXPIRATION_TIME: Duration = Duration::from_secs(60 * 60 * 24 * 30);

impl Session {
    pub fn from_cookies(cookies: &HashMap<&str, Cookie>) -> Result<Option<Session>, Error> {
        let Some(cookie) = cookies.get("session") else { return Ok(None); };
        Ok(Some(serde_json::from_str(cookie.value())?))
    }

    pub fn create(user: User) -> Session {
        Session { user }
    }

    pub fn cookie_login(&self) -> Cookie {
        cookie_raw(Some(self), EXPIRATION_TIME)
    }

    pub fn cookie_logout() -> Cookie<'static> {
        cookie_raw(None, Duration::ZERO)
    }
}

impl slog::KV for Session {
    fn serialize(
        &self,
        record: &slog::Record,
        serializer: &mut dyn slog::Serializer,
    ) -> slog::Result {
        slog::Value::serialize(&self.user, record, "session", serializer)
    }
}

fn cookie_raw(session: Option<&Session>, max_age: Duration) -> Cookie {
    // Default SameSite is specified to be Lax, but some browsers (Firefox) haven't made the switch
    // from None to Lax yet.
    // TODO: Encrypt the cookie, or store sessions in the database.
    Cookie::build(
        "session",
        session
            .map_or(Ok(String::new()), serde_json::to_string)
            .unwrap(),
    )
    .max_age(max_age.try_into().unwrap())
    .secure(true)
    .http_only(true)
    .same_site(SameSite::Lax)
    .finish()
}
