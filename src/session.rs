use crate::crypto::{Crypto, Signature};
use crate::error::Error;
use crate::user::User;
use cookie::{Cookie, SameSite};
use std::collections::HashMap;
use std::convert::TryInto;
use std::fmt;
use std::str::FromStr;
use std::time::Duration;
use uuid::Uuid;

pub struct Session {
    session: UnsignedSession,
    signature: Signature,
}

struct UnsignedSession {
    id: Uuid,
    user: User,
}

const EXPIRATION_TIME: Duration = Duration::from_secs(60 * 60 * 24 * 30);

impl Session {
    pub fn from_cookies(
        cookies: &HashMap<&str, Cookie>,
        crypto: &Crypto,
    ) -> Result<Option<Session>, Error> {
        let Some(cookie) = cookies.get("session") else { return Ok(None); };
        let (session_str, signature) = cookie.value().rsplit_once('.').unwrap();
        let session = session_str.parse()?;
        Ok(Some(Session {
            session,
            signature: crypto.verify(session_str.as_bytes(), &hex::decode(signature)?)?,
        }))
    }

    pub fn create(user: User, crypto: &Crypto) -> Session {
        let session = UnsignedSession::create(user);
        let signature = crypto.sign(session.to_string().as_bytes());
        Session { session, signature }
    }

    pub fn user(&self) -> &User {
        &self.session.user
    }

    pub fn cookie_login(&self) -> Cookie {
        cookie_raw(Some(self), EXPIRATION_TIME)
    }

    pub fn cookie_logout() -> Cookie<'static> {
        cookie_raw(None, Duration::ZERO)
    }
}

impl UnsignedSession {
    pub fn create(user: User) -> UnsignedSession {
        UnsignedSession {
            id: Uuid::new_v4(),
            user,
        }
    }
}

impl slog::KV for Session {
    fn serialize(
        &self,
        _record: &slog::Record,
        serializer: &mut dyn slog::Serializer,
    ) -> slog::Result {
        serializer.emit_str("session", &self.session.id.to_string())
    }
}

impl FromStr for UnsignedSession {
    type Err = Error;

    fn from_str(s: &str) -> Result<UnsignedSession, Error> {
        let (id, user_id) = s.split_once('.').unwrap();
        Ok(UnsignedSession {
            id: id.parse()?,
            user: User {
                id: user_id.parse()?,
            },
        })
    }
}

impl fmt::Display for UnsignedSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.id, self.user.id)
    }
}

fn cookie_raw(session: Option<&Session>, max_age: Duration) -> Cookie {
    // Default SameSite is specified to be Lax, but some browsers (Firefox) haven't made the switch
    // from None to Lax yet.
    Cookie::build(
        "session",
        session.map_or(String::new(), |session| {
            format!(
                "{}.{}",
                session.session,
                hex::encode(&session.signature.hash)
            )
        }),
    )
    .max_age(max_age.try_into().unwrap())
    .path("/")
    .secure(true)
    .http_only(true)
    .same_site(SameSite::Lax)
    .finish()
}
