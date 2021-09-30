use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request, Response, Server};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio_postgres::NoTls;

fn main() {
    run_async().unwrap();
}

fn run_async() -> Result<(), Box<dyn std::error::Error>> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()?;
    runtime.block_on(run())
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let database_url = env!("DATABASE_URL");
    let database_config = database_url.parse::<tokio_postgres::Config>()?;
    let (database, database_task) = database_config.connect(NoTls).await?;
    let database = Arc::new(database);
    let address = SocketAddr::from(([127, 0, 0, 1], 8000));
    let service_factory = make_service_fn(|_conn| {
        let database = database.clone();
        async move { Ok::<_, Infallible>(service_fn(move |req| hello_world(req, database.clone()))) }
    });
    let server = Server::bind(&address).serve(service_factory);
    tokio::spawn(database_task);
    server
        .await
        .map_err(|err| Box::new(err) as Box<dyn std::error::Error + 'static>)
}

async fn hello_world(
    _req: Request<Body>,
    database: Arc<tokio_postgres::Client>,
) -> Result<Response<Body>, tokio_postgres::Error> {
    let row = database.query_one("SELECT $1", &[&"Hello, world!"]).await?;
    let answer: String = row.get(0);
    Ok(Response::new(answer.into()))
}
