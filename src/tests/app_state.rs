use axum::{routing::get, Router};

use crate::app::AxumApp;

#[derive(Clone)]
struct AppState;

fn routes(state: AppState) -> Router {
    Router::new().route("/", get(get_index)).with_state(state)
}

async fn get_index() -> &'static str {
    "index"
}

#[tokio::test]
async fn get_index_page() {
    let app = AxumApp::new(routes(AppState));
    let server = app.spawn_test_server().unwrap();

    let response = server.get("/").await;
    response.assert_text("index");
}
