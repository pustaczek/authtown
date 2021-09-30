use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHasher};
use cookie::Cookie;
use hyper::header::{COOKIE, SET_COOKIE};
use hyper::server::conn::AddrStream;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, Server, StatusCode};
use serde::Deserialize;
use slog::{error, info, o, Drain, Logger};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio_postgres::NoTls;
use uuid::Uuid;

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

const SESSION_EXPIRE_TIME: Duration = Duration::from_secs(60 * 60 * 24 * 30);

fn main() {
    let instance_id = Uuid::new_v4();
    let log = init_logger(instance_id);
    info!(log, "Launching server"; "version" => env!("CARGO_PKG_VERSION"));
    run_async(log).unwrap();
}

fn init_logger(instance_id: Uuid) -> Logger {
    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::CompactFormat::new(decorator).build().fuse();
    let drain = slog_async::Async::new(drain).build().fuse();
    Logger::root(drain, o!("instance" => instance_id.to_string()))
}

fn run_async(log: Logger) -> Result<(), Error> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()?;
    runtime.block_on(run(log))
}

async fn run(log: Logger) -> Result<(), Error> {
    let database_url = std::env::var("DATABASE_URL")?;
    let database_config = database_url.parse::<tokio_postgres::Config>()?;
    let (database, database_task) = database_config.connect(NoTls).await?;
    let database = Arc::new(database);
    let address = SocketAddr::from(([127, 0, 0, 1], 8000));
    let service_factory = make_service_fn(|conn: &AddrStream| {
        let conn_id = Uuid::new_v4();
        let conn_log = log.new(o!("connection" => conn_id.to_string()));
        info!(conn_log, "Connection accepted"; "ip" => conn.remote_addr());
        let database = database.clone();
        async move {
            Ok::<_, Infallible>(service_fn(move |req| {
                let req_id = Uuid::new_v4();
                let req_log = conn_log.new(o!("request" => req_id.to_string()));
                info!(req_log, "HTTP request received"; "method" => req.method().to_string(), "endpoint" => req.uri().to_string());
                catcher(req, database.clone(), req_log)
            }))
        }
    });
    let server = Server::bind(&address).serve(service_factory);
    tokio::spawn(database_task);
    Ok(server.await?)
}

async fn catcher(
    req: Request<Body>,
    database: Arc<tokio_postgres::Client>,
    log: Logger,
) -> Result<Response<Body>, Error> {
    match router(req, database, log).await {
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
    log: Logger,
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
            info!(log, "Registering a new account"; "username" => &body.username);
            let row = database
                .query_one(
                    "INSERT INTO users (username, password_phc) VALUES ($1, $2) RETURNING id;",
                    &[&body.username, &hash.to_string()],
                )
                .await?;
            let user_id: i32 = row.get(0);
            Ok(Response::builder()
                .status(StatusCode::OK)
                .header(SET_COOKIE, session_cookie(user_id, SESSION_EXPIRE_TIME))
                .body(user_id.to_string().into())
                .unwrap())
        }
        (&Method::POST, "/auth/logout") => {
            let cookies = req.headers().get(COOKIE).unwrap();
            let cookie = Cookie::parse(cookies.to_str().unwrap()).unwrap();
            if cookie.name() == "session" {
                match cookie.value().parse::<i32>() {
                    Ok(user_id) => Ok(Response::builder()
                        .status(StatusCode::OK)
                        .header(SET_COOKIE, session_cookie(user_id, Duration::ZERO))
                        .body(Body::empty())
                        .unwrap()),
                    Err(e) => Ok(Response::builder()
                        .status(StatusCode::BAD_REQUEST)
                        .body(e.to_string().into())
                        .unwrap()),
                }
            } else {
                Ok(Response::builder()
                    .status(StatusCode::OK)
                    .body("Already logged out".into())
                    .unwrap())
            }
        }
        _ => Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::empty())
            .unwrap()),
    }
}

fn session_cookie(user_id: i32, max_age: Duration) -> String {
    // Default SameSite is specified to be Lax, but some browsers (Firefox) haven't made the switch
    // from None to Lax yet.
    // TODO: Encrypt the cookie, or store sessions in the database.
    format!(
        "session={}; Max-Age={}; Secure; HttpOnly; SameSite=Lax",
        user_id,
        max_age.as_secs()
    )
}
