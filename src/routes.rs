use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use lazy_static::lazy_static;
use rand::seq::IteratorRandom;
use serde_json::{json, Value};
use std::env;
use std::{thread::sleep, time::Duration};
use tracing::{error, info};

lazy_static! {
    pub static ref DEFAULT_RESPONSE_BODY: Value = json!({
        "statusCode": 500,
        "body": "hello, Chaos!!!"
    });
}

#[derive(Clone)]
pub struct AppState {
    pub runtime_api_address: String,
}

const ENABLE_LATENCY_ENV_NAME: &str = "CHAOS_EXTENSION__LAMBDA__ENABLE_LATENCY";
const LATENCY_PROBABILITY_ENV_NAME: &str = "CHAOS_EXTENSION__LAMBDA__LATENCY_PROBABILITY";
const LATENCY_VALUE_ENV_NAME: &str = "CHAOS_EXTENSION__LAMBDA__LATENCY_VALUE";

const ENABLE_CHANGE_RESPONSE_BODY_ENV_NAME: &str =
    "CHAOS_EXTENSION__RESPONSE__ENABLE_CHANGE_RESPONSE_BODY";
const REPONSE_PROBABILITY_ENV_NAME: &str = "CHAOS_EXTENSION__RESPONSE__CHANGE_RESPONSE_PROBABILITY";
const DEFAULT_RESPONSE_ENV_NAME: &str = "CHAOS_EXTENSION__RESPONSE__DEFAULT_RESPONSE";

const ENABLE_TCP_BLOCK_ENV_NAME: &str = "CHAOS_EXTENSION__LAMBDA__ENABLE_TCP_BLOCK";
const TCP_BLOCK_PORTS_ENV_NAME: &str = "CHAOS_EXTENSION__LAMBDA__TCP_BLOCK_PORTS";

pub async fn get_next_invocation(State(state): State<AppState>) -> impl IntoResponse {
    info!("get_next_invocation was invoked");
    let resp = reqwest::get(format!(
        "http://{}/2018-06-01/runtime/invocation/next",
        state.runtime_api_address
    ))
    .await
    .unwrap();

    let enable_timeout = str_to_bool(
        std::env::var(ENABLE_LATENCY_ENV_NAME)
            .unwrap_or("false".to_string())
            .as_str(),
        false,
    );

    let timeout_probability = std::env::var(LATENCY_PROBABILITY_ENV_NAME)
        .unwrap_or("0.9".to_string())
        .parse()
        .unwrap_or(0.9);

    let latency = std::env::var(LATENCY_VALUE_ENV_NAME)
        .unwrap_or("900".to_string())
        .parse()
        .unwrap_or(15 * 60);
    let probability = rand::random::<f64>();
    if enable_timeout {
        info!("Latency injection enabled");
        info!(
            "Chosen probability - {}, configured probability - {}",
            probability, timeout_probability
        );

        if probability < timeout_probability {
            info!("Added latency to Lambda - {} seconds", latency);
            sleep(Duration::from_secs(latency));
        }
    }

    let mut headers = resp.headers().clone();
    headers.remove("transfer-encoding");
    let status = resp.status().as_u16();
    let status = StatusCode::from_u16(status).unwrap();

    let data = resp.text().await.unwrap();

    (status, headers, data)
}

pub async fn post_invoke_response(
    State(state): State<AppState>,
    Path(request_id): Path<String>,
    data: String,
) -> impl IntoResponse {
    info!("post_invoke_response was invoked");
    let enable_change_reponse = str_to_bool(
        std::env::var(ENABLE_CHANGE_RESPONSE_BODY_ENV_NAME)
            .unwrap_or("false".to_string())
            .as_str(),
        false,
    );

    let response_probability = std::env::var(REPONSE_PROBABILITY_ENV_NAME)
        .unwrap_or("0.9".to_string())
        .parse()
        .unwrap_or(0.9);

    let probability = rand::random::<f64>();

    let mut body = data;

    if enable_change_reponse {
        info!("Change response injection enabled");
        info!(
            "Chosen probability - {}, configured probability - {}",
            probability, response_probability
        );

        if probability < response_probability {
            body = std::env::var(DEFAULT_RESPONSE_ENV_NAME)
                .unwrap_or(DEFAULT_RESPONSE_BODY.to_string());
            info!("Changing response body - {}", &body);
        }
    }

    let resp = reqwest::Client::new()
        .post(format!(
            "http://{}/2018-06-01/runtime/invocation/{}/response",
            state.runtime_api_address, request_id
        ))
        .body(body.clone())
        .send()
        .await
        .unwrap();

    let headers = resp.headers().clone();
    let status = resp.status().as_u16();
    let status = StatusCode::from_u16(status).unwrap();

    (status, headers, resp.text().await.unwrap())
}

pub async fn post_initialization_error(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: String,
) -> impl IntoResponse {
    info!("post_initialization_error was invoked");
    let resp = reqwest::Client::new()
        .post(format!(
            "http://{}/2018-06-01/runtime/init/error",
            state.runtime_api_address
        ))
        .body(body.clone())
        .headers(headers)
        .send()
        .await
        .unwrap();

    let headers = resp.headers().clone();
    let status = resp.status().as_u16();
    let status = StatusCode::from_u16(status).unwrap();

    (status, headers, body)
}

pub async fn post_invoke_error(
    State(state): State<AppState>,
    Path(request_id): Path<String>,
    headers: HeaderMap,
    body: String,
) -> impl IntoResponse {
    info!("post_invoke_error was invoked");
    let resp = reqwest::Client::new()
        .post(format!(
            "http://{}/2018-06-01/runtime/invocation/{}/error",
            state.runtime_api_address, request_id
        ))
        .body(body.clone())
        .headers(headers)
        .send()
        .await
        .unwrap();

    let headers = resp.headers().clone();
    let status = resp.status().as_u16();
    let status = StatusCode::from_u16(status).unwrap();

    (status, headers, body)
}

pub async fn block_tcp_ports() {
    let enable_tcp_block = str_to_bool(
        std::env::var(ENABLE_TCP_BLOCK_ENV_NAME)
            .unwrap_or("false".to_string())
            .as_str(),
        false,
    );

    if !enable_tcp_block {
        return;
    }

    let blocked_ports = std::env::var(TCP_BLOCK_PORTS_ENV_NAME)
        .unwrap_or("".to_string())
        .split(',')
        .filter_map(|s| s.parse::<u16>().ok())
        .collect::<Vec<u16>>();

    if blocked_ports.is_empty() {
        return;
    }

    let probability = rand::random::<f64>();
    let block_probability = 1;
    if probability < block_probability {
        let port_to_block = blocked_ports.choose(&mut rand::thread_rng());
        if let Some(port) = port_to_block {
            info!("Blocking TCP port: {}", port);
            block_port(*port).await;
        }
    }
}

async fn block_port(port: u16) {
    let listener = TcpListener::bind(format!("0.0.0.0:{}", port));
    match listener {
        Ok(_) => {
            info!("Successfully blocked port: {}", port);
        }
        Err(_) => {
            error!("Failed to block port: {}", port);
        }
    }
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route(
            "/2018-06-01/runtime/invocation/next",
            get(get_next_invocation),
        )
        .route(
            "/2018-06-01/runtime/invocation/:request_id/response",
            post(post_invoke_response),
        )
        .route(
            "/2018-06-01/runtime/init/error",
            post(post_initialization_error),
        )
        .route(
            "/2018-06-01/runtime/invocation/:request_id/error",
            post(post_invoke_error),
        )
        .with_state(state)
}

fn str_to_bool(input: &str, default: bool) -> bool {
    match input.to_lowercase().as_str() {
        "true" => true,
        "false" => false,
        _ => {
            error!("Error: Invalid input string. Expected 'true' or 'false'.");
            default
        }
    }
}
