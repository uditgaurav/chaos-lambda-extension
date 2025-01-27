use axum::Server;
use lambda_extension::{service_fn, Error, Extension, LambdaEvent};
use tokio::task;
use tracing::{debug, info};
use tracing_subscriber::EnvFilter;
use std::env;

mod routes;

#[tokio::main]
async fn main() -> Result<(), Error> {

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_target(false)
        .without_time()
        .init();

    let state = routes::AppState {
        runtime_api_address: std::env::var("AWS_LAMBDA_RUNTIME_API")
            .expect("Missing AWS_LAMBDA_RUNTIME_API!"),
    };
    debug!(
        "Pulling AWS_LAMBDA_RUNTIME_API endpoint - {}",
        state.runtime_api_address
    );

    let app = routes::router(state);

    info!("Chaos extension is enabled");

    routes::block_tcp_ports().await;

    let server = Server::bind(&"0.0.0.0:9100".parse().unwrap()).serve(app.into_make_service());

    task::spawn(async move {
        server.await.unwrap();
    });

    Extension::new()
        .with_events(&[])
        .with_events_processor(service_fn(boot_extension))
        .run()
        .await
}

async fn boot_extension(event: LambdaEvent) -> Result<(), Error> {
    Ok(())
}
