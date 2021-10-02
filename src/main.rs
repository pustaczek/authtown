#![feature(backtrace, let_else, once_cell)]

mod crypto;
mod error;
mod session;
mod user;
mod util;

use crate::crypto::Crypto;
use crate::session::Session;
use crate::user::UserStore;
use crate::util::env_var;
use cookie::Cookie;
use error::Error;
use hyper::header::{COOKIE, LOCATION, SET_COOKIE};
use hyper::server::conn::AddrStream;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, Server, StatusCode};
use prometheus::{
    register_histogram_vec, register_int_counter_vec, Encoder, HistogramVec, IntCounterVec,
};
use serde::{Deserialize, Serialize};
use slog::{error, info, o, Drain, Logger};
use std::collections::HashMap;
use std::convert::Infallible;
use std::lazy::SyncLazy;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tera::Tera;
use tokio_postgres::NoTls;
use uuid::Uuid;

#[derive(Debug, Deserialize)]
struct AuthRegisterRequest {
    username: String,
    password: String,
}

#[derive(Debug, Deserialize)]
struct AuthLoginRequest {
    username: String,
    password: String,
}

#[derive(Serialize)]
struct Ctx {
    user: Option<CtxUser>,
}

#[derive(Serialize)]
struct CtxUser {
    id: i32,
}

static METRIC_HTTP_REQUEST_COUNT: SyncLazy<IntCounterVec> = SyncLazy::new(|| {
    register_int_counter_vec!(
        "authtown_http_request_count",
        "Number of HTTP requests received",
        &["method", "endpoint"]
    )
    .unwrap()
});
static METRIC_HTTP_REQUEST_LATENCY: SyncLazy<HistogramVec> = SyncLazy::new(|| {
    register_histogram_vec!(
        "authtown_http_request_latency",
        "Latency of HTTP requests",
        &["method", "endpoint"]
    )
    .unwrap()
});

fn main() {
    let log = init_logger();
    match run_async(log.clone()) {
        Ok(()) => (),
        Err(e) => {
            error!(log, "Critical server failure"; e.log_message(), e.log_backtrace());
        }
    }
}

fn init_logger() -> Logger {
    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::CompactFormat::new(decorator).build().fuse();
    let drain = slog_async::Async::new(drain).build().fuse();
    Logger::root(drain, o!())
}

fn run_async(log: Logger) -> Result<(), Error> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()?;
    runtime.block_on(run(log))
}

async fn run(log: Logger) -> Result<(), Error> {
    let database_url = env_var("DATABASE_URL")?;
    let database_config = database_url.parse::<tokio_postgres::Config>()?;
    let (database, database_task) = database_config.connect(NoTls).await?;
    let database = Arc::new(database);
    let tera = Arc::new(Tera::new("templates/*.html")?);
    let crypto = Arc::new(Crypto::from_env()?);
    let address = SocketAddr::from(([127, 0, 0, 1], 8000));
    let service_factory = make_service_fn(|conn: &AddrStream| {
        let log = log.clone();
        let database = database.clone();
        let tera = tera.clone();
        let crypto = crypto.clone();
        let conn_ip = conn.remote_addr().ip();
        async move {
            Ok::<_, Infallible>(service_fn(move |req| {
                let start_time = Instant::now();
                let req_method_str = req.method().to_string();
                let req_path_str = req.uri().path().to_owned();
                let req_id = Uuid::new_v4();
                let req_log = log.new(o!("request" => req_id.to_string()));
                info!(req_log, "HTTP request received"; "method" => req.method().as_str(), "endpoint" => req.uri().path(), "ip" => conn_ip.to_string());
                let database = database.clone();
                let tera = tera.clone();
                let crypto = crypto.clone();
                async move {
                    let response = catcher(req, database, tera, crypto, req_log).await;
                    let finish_time = Instant::now();
                    METRIC_HTTP_REQUEST_LATENCY
                        .with_label_values(&[req_method_str.as_str(), req_path_str.as_str()])
                        .observe((finish_time - start_time).as_nanos() as f64);
                    Ok::<_, Infallible>(response)
                }
            }))
        }
    });
    let server = Server::bind(&address).serve(service_factory);
    tokio::spawn(database_task);
    info!(log, "Listening on http://{}", address);
    Ok(server.await?)
}

async fn catcher(
    req: Request<Body>,
    database: Arc<tokio_postgres::Client>,
    tera: Arc<Tera>,
    crypto: Arc<Crypto>,
    log: Logger,
) -> Response<Body> {
    match router(req, database, tera, crypto, &log).await {
        Ok(resp) => {
            info!(log, "HTTP request successful"; "status" => resp.status().as_u16());
            resp
        }
        Err(e) => {
            error!(log, "HTTP request failed"; "status" => 500, e.log_message(), e.log_backtrace());
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(e.to_string().into())
                .unwrap()
        }
    }
}

async fn router(
    mut req: Request<Body>,
    database: Arc<tokio_postgres::Client>,
    tera: Arc<Tera>,
    crypto: Arc<Crypto>,
    log: &Logger,
) -> Result<Response<Body>, Error> {
    METRIC_HTTP_REQUEST_COUNT
        .with_label_values(&[req.method().as_str(), req.uri().path()])
        .inc();
    let cookies = get_cookies(&req)?;
    let session = Session::from_cookies(&cookies, &*crypto)?;
    if let Some(session) = &session {
        info!(log, "User is logged in"; session, session.user());
    } else {
        info!(log, "User is not logged in");
    }
    let context = tera::Context::from_serialize(Ctx {
        user: session.as_ref().map(|session| CtxUser {
            id: session.user().id,
        }),
    })?;
    match (req.method(), req.uri().path()) {
        (&Method::GET, "/") => Ok(Response::builder()
            .status(StatusCode::OK)
            .body(tera.render("index.html", &context)?.into())
            .unwrap()),
        (&Method::POST, "/auth/register") => {
            let body_bytes = hyper::body::to_bytes(req.body_mut()).await?;
            let body: AuthRegisterRequest = serde_urlencoded::from_bytes(&body_bytes)?;
            info!(log, "Registering a new account"; "username" => &body.username);
            let user_store = UserStore::new(&*database);
            let user = user_store.insert(&body.username, &body.password).await?;
            let session = Session::create(user, &*crypto);
            info!(log, "Logged in after registration"; &session);
            Ok(Response::builder()
                .status(StatusCode::SEE_OTHER)
                .header(LOCATION, "/")
                .header(SET_COOKIE, session.cookie_login().to_string())
                .body(Body::empty())
                .unwrap())
        }
        (&Method::POST, "/auth/login") => {
            let body_bytes = hyper::body::to_bytes(req.body_mut()).await?;
            let body: AuthLoginRequest = serde_urlencoded::from_bytes(&body_bytes)?;
            info!(log, "Logging in"; "username" => &body.username);
            let user_store = UserStore::new(&*database);
            let user = user_store
                .get_and_verify(&body.username, &body.password)
                .await?;
            let session = Session::create(user, &*crypto);
            info!(log, "Logged in"; user, &session);
            Ok(Response::builder()
                .status(StatusCode::SEE_OTHER)
                .header(LOCATION, "/")
                .header(SET_COOKIE, session.cookie_login().to_string())
                .body(Body::empty())
                .unwrap())
        }
        (&Method::POST, "/auth/logout") => {
            info!(log, "Logging out");
            Ok(Response::builder()
                .status(StatusCode::SEE_OTHER)
                .header(LOCATION, "/")
                .header(SET_COOKIE, Session::cookie_logout().to_string())
                .body(Body::empty())
                .unwrap())
        }
        (&Method::GET, "/metrics") => {
            info!(log, "Scrapping metrics");
            let encoder = prometheus::TextEncoder::new();
            let families = prometheus::gather();
            let mut buffer = Vec::new();
            encoder.encode(&families, &mut buffer).unwrap();
            Ok(Response::builder()
                .status(StatusCode::OK)
                .body(buffer.into())
                .unwrap())
        }
        _ => Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::empty())
            .unwrap()),
    }
}

fn get_cookies(request: &Request<Body>) -> Result<HashMap<&str, Cookie>, Error> {
    let Some(header) = request.headers().get(COOKIE) else { return Ok(HashMap::new()); };
    Ok(header
        .to_str()?
        .split("; ")
        .map(|cookie| Cookie::parse(cookie).map(|cookie| (cookie.name_raw().unwrap(), cookie)))
        .collect::<Result<HashMap<_, _>, _>>()?)
}
