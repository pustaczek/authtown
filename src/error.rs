use slog::SingleKV;
use std::backtrace::Backtrace;
use std::error::Error as StdError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("database error")]
    Database(#[from] tokio_postgres::Error, Backtrace),
    #[error("network or http error")]
    Http(#[from] hyper::Error, Backtrace),
    #[error("environment variable {name} missing")]
    Environment {
        name: &'static str,
        source: std::env::VarError,
        backtrace: Backtrace,
    },
    #[error("JSON deserialization error")]
    Json(#[from] serde_json::Error, Backtrace),
    #[error("IO error")]
    Io(#[from] std::io::Error, Backtrace),
    #[error("HTML templating error")]
    HtmlTemplate(#[from] tera::Error, Backtrace),
}

impl Error {
    pub fn log_message(&self) -> SingleKV<String> {
        let mut error: &dyn StdError = &self;
        let mut buf = error.to_string().replace('\n', " ");
        while let Some(source) = error.source() {
            let source_msg = source.to_string().replace('\n', " ");
            if !buf.contains(&source_msg) {
                buf += &format!(": {}", source_msg);
            }
            error = source;
        }
        SingleKV::from(("message", buf))
    }

    pub fn log_backtrace(&self) -> SingleKV<Option<String>> {
        SingleKV::from(("backtrace", self.backtrace().map(Backtrace::to_string)))
    }
}
