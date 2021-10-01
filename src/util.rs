use crate::error::Error;
use std::backtrace::Backtrace;

pub fn env_var(name: &'static str) -> Result<String, Error> {
    match std::env::var(name) {
        Ok(value) => Ok(value),
        Err(source) => Err(Error::Environment {
            name,
            source,
            backtrace: Backtrace::capture(),
        }),
    }
}
