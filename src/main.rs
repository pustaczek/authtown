use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHasher};
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, Server, StatusCode};
use serde::Deserialize;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use thiserror::Error;
use tokio_postgres::NoTls;

#[derive(Debug, Deserialize)]
struct AuthRegisterRequest {
    username: String,
    password: String,
}

#[derive(Debug, Error)]
enum Error {
    #[error("database failure")]
    Database(#[from] tokio_postgres::Error),
    #[error("http error")]
    Http(#[from] hyper::Error),
    #[error("environment variable missing")]
    Environment(#[from] std::env::VarError),
    #[error("json deserialization error")]
    Json(#[from] serde_json::Error),
    #[error("IO error")]
    Io(#[from] std::io::Error),
}

fn main() {
    run_async().unwrap();
}

fn run_async() -> Result<(), Error> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()?;
    runtime.block_on(run())
}

async fn run() -> Result<(), Error> {
    let database_url = std::env::var("DATABASE_URL")?;
    let database_config = database_url.parse::<tokio_postgres::Config>()?;
    let (database, database_task) = database_config.connect(NoTls).await?;
    let database = Arc::new(database);
    let address = SocketAddr::from(([127, 0, 0, 1], 8000));
    let service_factory = make_service_fn(|_conn| {
        let database = database.clone();
        async move { Ok::<_, Infallible>(service_fn(move |req| catcher(req, database.clone()))) }
    });
    let server = Server::bind(&address).serve(service_factory);
    tokio::spawn(database_task);
    Ok(server.await?)
}

async fn catcher(
    req: Request<Body>,
    database: Arc<tokio_postgres::Client>,
) -> Result<Response<Body>, Error> {
    match router(req, database).await {
        Ok(resp) => Ok(resp),
        Err(e) => {
            println!("{:#?}", e);
            Ok(Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(e.to_string().into())
                .unwrap())
        }
    }
}

async fn router(
    mut req: Request<Body>,
    database: Arc<tokio_postgres::Client>,
) -> Result<Response<Body>, Error> {
    match (req.method(), req.uri().path()) {
        (&Method::POST, "/auth/register") => {
            let body: AuthRegisterRequest =
                serde_json::from_slice(&hyper::body::to_bytes(req.body_mut()).await?)?;
            let argon2 = Argon2::default();
            let salt = SaltString::generate(OsRng);
            let hash = argon2
                .hash_password(body.password.as_bytes(), &salt)
                .unwrap();
            let written_rows = database
                .execute(
                    "INSERT INTO users (username, password_phc) VALUES ($1, $2) RETURNING id;",
                    &[&body.username, &hash.to_string()],
                )
                .await?;
            assert_eq!(written_rows, 1);
            Ok(Response::builder()
                .status(StatusCode::OK)
                .body(format!("{:#?}", body).into())
                .unwrap())
        }
        _ => Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::empty())
            .unwrap()),
    }
}
