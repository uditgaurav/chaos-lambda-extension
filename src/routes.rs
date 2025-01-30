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
use tokio::{net::TcpListener, time::{sleep, Duration}};
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
    .unwrap_or_else(|e| {
        error!("Failed to fetch next invocation: {}", e);
        reqwest::Response::new(reqwest::StatusCode::INTERNAL_SERVER_ERROR)
    });

    let enable_timeout = str_to_bool(
        std::env::var(ENABLE_LATENCY_ENV_NAME)
            .unwrap_or_else(|_| "false".to_string())
            .as_str(),
        false,
    );

    let timeout_probability = std::env::var(LATENCY_PROBABILITY_ENV_NAME)
        .unwrap_or_else(|_| "0.9".to_string())
        .parse()
        .unwrap_or(0.9);

    let latency = std::env::var(LATENCY_VALUE_ENV_NAME)
        .unwrap_or_else(|_| "900".to_string())
        .parse()
        .unwrap_or(15 * 60);

    let probability = rand::random::<f64>();
    if enable_timeout && probability < timeout_probability {
        info!("Injecting latency of {} seconds", latency);
        sleep(Duration::from_secs(latency)).await; // Non-blocking async sleep
    }

    let mut headers = resp.headers().clone();
    headers.remove("transfer-encoding");
    let status = resp.status().as_u16();
    let status = StatusCode::from_u16(status).unwrap();

    let data = resp.text().await.unwrap_or_else(|_| "No data".to_string());

    (status, headers, data)
}

pub async fn post_invoke_response(
    State(state): State<AppState>,
    Path(request_id): Path<String>,
    data: String,
) -> impl IntoResponse {
    info!("post_invoke_response was invoked");

    let enable_change_response = str_to_bool(
        std::env::var(ENABLE_CHANGE_RESPONSE_BODY_ENV_NAME)
            .unwrap_or_else(|_| "false".to_string())
            .as_str(),
        false,
    );

    let response_probability = std::env::var(REPONSE_PROBABILITY_ENV_NAME)
        .unwrap_or_else(|_| "0.9".to_string())
        .parse()
        .unwrap_or(0.9);

    let probability = rand::random::<f64>();

    let mut body = data;

    if enable_change_response && probability < response_probability {
        body = std::env::var(DEFAULT_RESPONSE_ENV_NAME)
            .unwrap_or_else(|_| DEFAULT_RESPONSE_BODY.to_string());
        info!("Changing response body to default.");
    }

    let resp = reqwest::Client::new()
        .post(format!(
            "http://{}/2018-06-01/runtime/invocation/{}/response",
            state.runtime_api_address, request_id
        ))
        .body(body.clone())
        .send()
        .await
        .unwrap_or_else(|e| {
            error!("Failed to send invoke response: {}", e);
            reqwest::Response::new(reqwest::StatusCode::INTERNAL_SERVER_ERROR)
        });

    (resp.status(), resp.headers().clone(), resp.text().await.unwrap_or_default())
}

pub async fn block_tcp_ports() {
    let enable_tcp_block = str_to_bool(
        std::env::var(ENABLE_TCP_BLOCK_ENV_NAME)
            .unwrap_or_else(|_| "false".to_string())
            .as_str(),
        false,
    );

    if !enable_tcp_block {
        return;
    }

    let blocked_ports = std::env::var(TCP_BLOCK_PORTS_ENV_NAME)
        .unwrap_or_default()
        .split(',')
        .filter_map(|s| s.parse::<u16>().ok())
        .collect::<Vec<u16>>();

    let probability = rand::random::<f64>();
    let block_probability = 0.9;

    if probability < block_probability {
        if let Some(port) = blocked_ports.into_iter().choose(&mut rand::thread_rng()) {
            info!("Blocking TCP port: {}", port);
            tokio::spawn(async move {
                if let Ok(listener) = TcpListener::bind(format!("0.0.0.0:{}", port)).await {
                    info!("TCP port {} is blocked", port);
                    loop {
                        if let Err(e) = listener.accept().await {
                            error!("Failed to accept on port {}: {}", port, e);
                            break;
                        }
                    }
                } else {
                    error!("Failed to bind port {}", port);
                }
            });
        }
    }
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/2018-06-01/runtime/invocation/next", get(get_next_invocation))
        .route("/2018-06-01/runtime/invocation/:request_id/response", post(post_invoke_response))
        .route("/block-tcp", get(block_tcp_ports))
        .with_state(state)
}

fn str_to_bool(input: &str, default: bool) -> bool {
    match input.to_lowercase().as_str() {
        "true" => true,
        "false" => false,
        _ => default,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use std::env;
    use std::time::Instant;

    use tower::ServiceExt;
    use wiremock::matchers::{body_string, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn get_next_invocation_test_added_latency() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/2018-06-01/runtime/invocation/next"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;
        let app = router(AppState {
            runtime_api_address: mock_server.uri().replace("http://", ""),
        });

        env::set_var(ENABLE_LATENCY_ENV_NAME, "true");
        env::set_var(LATENCY_PROBABILITY_ENV_NAME, "1.0");
        env::set_var(LATENCY_VALUE_ENV_NAME, "2");

        let start = Instant::now();
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/2018-06-01/runtime/invocation/next")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let duration = start.elapsed();

        assert_eq!(response.status(), StatusCode::OK);
        assert!(duration.as_secs() >= 2);
    }
}
