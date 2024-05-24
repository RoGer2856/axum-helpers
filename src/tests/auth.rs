use std::time::Duration;

use async_trait::async_trait;
use axum::{
    extract::State,
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use uuid::Uuid;

use crate::{
    app::{AxumApp, AxumAppState},
    auth::{
        AuthError, AuthHandler, AuthLayer, AuthLoginResponse, AuthLogoutResponse,
        LoginInfoExtractor,
    },
};

const ACCESS_TOKEN_EXPIRATION_TIME_DURATION: Duration = Duration::from_secs(5 * 60 * 60 * 24);

#[derive(Clone)]
struct AppState;

impl AppState {
    fn login(&self, _loginname: impl Into<String>, _password: impl Into<String>) -> LoginInfo {
        LoginInfo {
            access_token: Uuid::new_v4().as_hyphenated().to_string(),
        }
    }
}

#[async_trait]
impl AuthHandler<LoginInfo> for AppState {
    async fn verify_access_token(&self, access_token: &str) -> Result<LoginInfo, AuthError> {
        Ok(LoginInfo {
            access_token: access_token.to_string(),
        })
    }

    async fn update_access_token(
        &self,
        access_token: String,
    ) -> Result<(String, Duration), AuthError> {
        Ok((access_token, ACCESS_TOKEN_EXPIRATION_TIME_DURATION))
    }
}

impl AxumAppState for AppState {
    fn routes(&self) -> Router {
        Router::new()
            .route("/public", get(get_public))
            .route("/private", get(get_private))
            .route("/hybrid", get(get_hybrid))
            .route("/api/login", post(api_login))
            .route("/api/logout", post(api_logout))
            .route_layer(AuthLayer::new(self.clone()))
            .with_state(self.clone())
    }
}

async fn get_public() -> &'static str {
    "public"
}

async fn get_private(
    LoginInfoExtractor(_login_info): LoginInfoExtractor<LoginInfo>,
) -> &'static str {
    "private"
}

async fn get_hybrid(login_info: Option<LoginInfoExtractor<LoginInfo>>) -> &'static str {
    if login_info.is_some() {
        "authenticated"
    } else {
        "unauthenticated"
    }
}

#[derive(Clone)]
struct LoginInfo {
    access_token: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct LoginRequest {
    loginname: String,
    password: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct LoginResponse {
    loginname: String,
}

async fn api_login(
    State(state): State<AppState>,
    Json(login_request): Json<LoginRequest>,
) -> Result<(StatusCode, AuthLoginResponse, Json<LoginResponse>), StatusCode> {
    let access_token = state
        .login(&login_request.loginname, login_request.password)
        .access_token;

    log::info!("User logged in, loginname = '{}'", login_request.loginname);

    Ok((
        StatusCode::OK,
        AuthLoginResponse::new(access_token, ACCESS_TOKEN_EXPIRATION_TIME_DURATION),
        Json(LoginResponse {
            loginname: login_request.loginname,
        }),
    ))
}

async fn api_logout(
    LoginInfoExtractor(_login_info): LoginInfoExtractor<LoginInfo>,
    State(_state): State<AppState>,
) -> Result<AuthLogoutResponse, StatusCode> {
    log::info!("User logged out");
    Ok(AuthLogoutResponse)
}

#[tokio::test]
async fn get_public_page() {
    let app = AxumApp::new(AppState);
    let server = app.spawn_test_server().unwrap();

    let response = server.get("/public").await;
    response.assert_text("public");
}

#[tokio::test]
async fn get_private_page_unauthenticated() {
    let app = AxumApp::new(AppState);
    let server = app.spawn_test_server().unwrap();

    let response = server.get("/private").await;
    response.assert_status_unauthorized();
}

#[tokio::test]
async fn get_private_page_authenticated() {
    let app = AxumApp::new(AppState);
    let mut server = app.spawn_test_server().unwrap();
    server.do_save_cookies();

    server
        .post("/api/login")
        .json(&LoginRequest {
            loginname: "loginname".into(),
            password: "password".into(),
        })
        .await;

    let response = server.get("/private").await;
    response.assert_text("private");
}

#[tokio::test]
async fn get_hybrid_page_unauthenticated() {
    let app = AxumApp::new(AppState);
    let server = app.spawn_test_server().unwrap();

    let response = server.get("/hybrid").await;
    response.assert_text("unauthenticated");
}

#[tokio::test]
async fn get_hybrid_page_authenticated() {
    let app = AxumApp::new(AppState);
    let mut server = app.spawn_test_server().unwrap();
    server.do_save_cookies();

    server
        .post("/api/login")
        .json(&LoginRequest {
            loginname: "loginname".into(),
            password: "password".into(),
        })
        .await;

    let response = server.get("/hybrid").await;
    response.assert_text("authenticated");
}

#[tokio::test]
async fn login_then_logout() {
    let app = AxumApp::new(AppState);
    let mut server = app.spawn_test_server().unwrap();
    server.do_save_cookies();

    let response = server.get("/hybrid").await;
    response.assert_text("unauthenticated");

    server
        .post("/api/login")
        .json(&LoginRequest {
            loginname: "loginname".into(),
            password: "password".into(),
        })
        .await;

    let response = server.get("/hybrid").await;
    response.assert_text("authenticated");

    server.post("/api/logout").await;

    let response = server.get("/hybrid").await;
    response.assert_text("unauthenticated");
}
