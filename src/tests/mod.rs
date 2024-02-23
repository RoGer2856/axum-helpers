use axum::{routing::get, Router};

use crate::app::{AxumApp, AxumAppState};

#[derive(Clone)]
struct AppState;

impl AxumAppState for AppState {
    fn routes(&self) -> Router {
        Router::new()
            .route("/", get(get_index))
            .with_state(self.clone())
    }
}

async fn get_index() -> &'static str {
    "index"
}

#[tokio::test]
async fn get_index_page() {
    let app = AxumApp::new(AppState);
    let server = app.spawn_test_server().unwrap();

    let response = server.get("/").await;

    response.assert_text("index");
}
