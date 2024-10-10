use std::convert::Infallible;

use axum::{routing::get, Router};

use crate::{
    app::{AxumApp, AxumAppState},
    response_http_header_mutator::ResponseHttpHeaderMutatorLayer,
};

#[derive(Clone)]
struct AppState;

impl AxumAppState for AppState {
    fn routes(&self) -> Router {
        Router::new()
            .route("/", get(get_index))
            .route_layer(ResponseHttpHeaderMutatorLayer::new(
                |req_headers, res_headers| {
                    *res_headers = req_headers.clone();
                    Ok::<(), Infallible>(())
                },
            ))
            .with_state(self.clone())
    }
}

async fn get_index() -> &'static str {
    "index"
}

#[tokio::test]
async fn copy_header_from_request() {
    let app = AxumApp::new(AppState);
    let server = app.spawn_test_server().unwrap();

    let response = server
        .get("/")
        .add_header("header-name-0".parse().unwrap(), "value-0".parse().unwrap())
        .add_header("header-name-1".parse().unwrap(), "value-1".parse().unwrap())
        .add_header("header-name-2".parse().unwrap(), "value-2".parse().unwrap())
        .await;

    response.assert_text("index");

    assert_eq!(response.headers().get("header-name-0").unwrap(), "value-0");
    assert_eq!(response.headers().get("header-name-1").unwrap(), "value-1");
    assert_eq!(response.headers().get("header-name-2").unwrap(), "value-2");
}
