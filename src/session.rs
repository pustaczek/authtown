use crate::error::Error;
use cookie::{Cookie, SameSite};
use std::collections::HashMap;
use std::convert::TryInto;
use std::time::Duration;

pub struct Session {
    pub user_id: i32,
}

const EXPIRATION_TIME: Duration = Duration::from_secs(60 * 60 * 24 * 30);

impl Session {
    pub fn from_cookies(cookies: &HashMap<&str, Cookie>) -> Result<Option<Session>, Error> {
        let Some(cookie) = cookies.get("session") else { return Ok(None); };
        let user_id = cookie.value().parse()?;
        Ok(Some(Session { user_id }))
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
        _record: &slog::Record,
        serializer: &mut dyn slog::Serializer,
    ) -> slog::Result {
        serializer.emit_i32("session", self.user_id)
    }
}

fn cookie_raw(session: Option<&Session>, max_age: Duration) -> Cookie {
    // Default SameSite is specified to be Lax, but some browsers (Firefox) haven't made the switch
    // from None to Lax yet.
    // TODO: Encrypt the cookie, or store sessions in the database.
    Cookie::build(
        "session",
        session.map_or(String::new(), |session| session.user_id.to_string()),
    )
    .max_age(max_age.try_into().unwrap())
    .secure(true)
    .http_only(true)
    .same_site(SameSite::Lax)
    .finish()
}
