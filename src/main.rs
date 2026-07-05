use axum::{routing::get, Json, Router};
use serde_json::{json, Value};

async fn healthz() -> Json<Value> {
    Json(json!({"status": "ok"}))
}

#[tokio::main]
async fn main() {
    let app = Router::new().route("/healthz", get(healthz));
    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

#[cfg(test)]
mod tests {
    use super::healthz;
    use serde_json::Value;

    #[tokio::test]
    async fn healthz_returns_ok() {
        let res = healthz().await;
        let val: Value = res.0;
        assert_eq!(val["status"], "ok");
    }
}