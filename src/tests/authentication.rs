use std::{collections::BTreeMap, sync::Arc, time::Duration};

use async_trait::async_trait;
use axum::{
    extract::State,
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};

use crate::{
    app::{AxumApp, AxumAppState},
    auth::{
        AccessTokenInfo, AuthError, AuthHandler, AuthLayer, AuthLoginResponse, AuthLogoutResponse,
        LoginInfoExtractor,
    },
};
use parking_lot::Mutex;
use uuid::Uuid;

const ACCESS_TOKEN_EXPIRATION_TIME_DURATION: Duration = Duration::from_secs(5 * 60 * 60 * 24);

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
struct AccessToken(pub String);

#[derive(Clone)]
struct AppState {
    logins: Arc<Mutex<BTreeMap<AccessToken, LoginInfo>>>,
}

impl AppState {
    fn new() -> Self {
        Self {
            logins: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    fn login(
        &mut self,
        loginname: impl Into<String>,
        _password: impl Into<String>,
    ) -> (AccessTokenInfo, LoginInfo) {
        let access_token_info = AccessTokenInfo::with_time_delta(
            Uuid::new_v4().as_hyphenated().to_string(),
            ACCESS_TOKEN_EXPIRATION_TIME_DURATION,
            None,
        );
        let loginname = loginname.into();

        let login_info = LoginInfo { loginname };

        self.logins.lock().insert(
            AccessToken(access_token_info.token().into()),
            login_info.clone(),
        );

        (access_token_info, login_info)
    }

    fn logout(&mut self, access_token: &str, login_info: &Arc<LoginInfo>) {
        self.logins.lock().remove(&AccessToken(access_token.into()));

        log::info!("User logged out, loginname = '{}'", login_info.loginname);
    }
}

#[async_trait]
impl AuthHandler<LoginInfo> for AppState {
    async fn verify_access_token(&mut self, access_token: &str) -> Result<LoginInfo, AuthError> {
        self.logins
            .lock()
            .get(&AccessToken(access_token.into()))
            .cloned()
            .ok_or_else(|| AuthError::InvalidAccessToken)
    }

    async fn update_access_token(
        &mut self,
        access_token: &str,
        _login_info: &Arc<LoginInfo>,
    ) -> Result<(String, Duration), AuthError> {
        Ok((access_token.into(), ACCESS_TOKEN_EXPIRATION_TIME_DURATION))
    }

    async fn invalidate_access_token(&mut self, access_token: &str, login_info: &Arc<LoginInfo>) {
        self.logout(access_token, login_info);
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
    loginname: String,
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
    State(mut state): State<AppState>,
    Json(login_request): Json<LoginRequest>,
) -> Result<(StatusCode, AuthLoginResponse, Json<LoginResponse>), StatusCode> {
    let (access_token, _login_info) = state.login(&login_request.loginname, login_request.password);

    log::info!("User logged in, loginname = '{}'", login_request.loginname);

    Ok((
        StatusCode::OK,
        AuthLoginResponse::new(access_token),
        Json(LoginResponse {
            loginname: login_request.loginname,
        }),
    ))
}

async fn api_logout(
    LoginInfoExtractor(_login_info): LoginInfoExtractor<LoginInfo>,
) -> Result<AuthLogoutResponse, StatusCode> {
    Ok(AuthLogoutResponse)
}

#[tokio::test]
async fn get_public_page() {
    let app = AxumApp::new(AppState::new());
    let server = app.spawn_test_server().unwrap();

    let response = server.get("/public").await;
    response.assert_status_ok();
    response.assert_text("public");
}

#[tokio::test]
async fn get_private_page_unauthenticated() {
    let app = AxumApp::new(AppState::new());
    let server = app.spawn_test_server().unwrap();

    let response = server.get("/private").await;
    response.assert_status_unauthorized();
}

#[tokio::test]
async fn get_private_page_authenticated() {
    let app = AxumApp::new(AppState::new());
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
    let app = AxumApp::new(AppState::new());
    let server = app.spawn_test_server().unwrap();

    let response = server.get("/hybrid").await;
    response.assert_status_ok();
    response.assert_text("unauthenticated");
}

#[tokio::test]
async fn get_hybrid_page_authenticated() {
    let app = AxumApp::new(AppState::new());
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
    response.assert_status_ok();
    response.assert_text("authenticated");
}

#[tokio::test]
async fn login_then_logout() {
    let app = AxumApp::new(AppState::new());
    let mut server = app.spawn_test_server().unwrap();
    server.do_save_cookies();

    let response = server.get("/hybrid").await;
    response.assert_status_ok();
    response.assert_text("unauthenticated");

    server
        .post("/api/login")
        .json(&LoginRequest {
            loginname: "loginname".into(),
            password: "password".into(),
        })
        .await;

    let response = server.get("/hybrid").await;
    response.assert_status_ok();
    response.assert_text("authenticated");

    server.post("/api/logout").await;

    let response = server.get("/hybrid").await;
    response.assert_status_ok();
    response.assert_text("unauthenticated");
}
