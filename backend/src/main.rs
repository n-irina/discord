use axum::{routing::get, Json, Router};
use serde_json::json;
use std::net::SocketAddr;

async fn health() -> Json<serde_json::Value> {
    Json(json!({
        "status": "ok"
    }))
}

#[tokio::main]
async fn main() {
    let app = Router::new().route("/health", get(health));

    let addr = SocketAddr::from(([127, 0, 0, 1], 4000));
    println!("Backend running on http://{}/health", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
