use std::convert::Infallible;

use axum::{routing::get, Router};

use crate::{app::AxumApp, response_http_header_mutator::ResponseHttpHeaderMutatorLayer};

#[derive(Clone)]
struct AppState;

fn routes(state: AppState) -> Router {
    Router::new()
        .route("/", get(get_index))
        .route_layer(ResponseHttpHeaderMutatorLayer::new(
            |req_headers, res_headers| {
                *res_headers = req_headers.clone();
                Ok::<(), Infallible>(())
            },
        ))
        .with_state(state)
}

async fn get_index() -> &'static str {
    "index"
}

#[tokio::test]
async fn copy_header_from_request() {
    let app = AxumApp::new(routes(AppState));
    let server = app.spawn_test_server().unwrap();

    let response = server
        .get("/")
        .add_header("header-name-0", "value-0")
        .add_header("header-name-1", "value-1")
        .add_header("header-name-2", "value-2")
        .await;

    response.assert_text("index");

    assert_eq!(response.headers().get("header-name-0").unwrap(), "value-0");
    assert_eq!(response.headers().get("header-name-1").unwrap(), "value-1");
    assert_eq!(response.headers().get("header-name-2").unwrap(), "value-2");
}
