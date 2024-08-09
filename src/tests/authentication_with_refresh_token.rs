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
        AccessTokenResponse, AuthHandler, AuthLayer, AuthLogoutResponse, LoginInfoExtractor,
        RefreshTokenExtractor, RefreshTokenResponse,
    },
};
use parking_lot::Mutex;
use uuid::Uuid;

const ACCESS_TOKEN_EXPIRATION_TIME_DURATION: Duration = Duration::from_secs(1);
const REFRESH_TOKEN_EXPIRATION_TIME_DURATION: Duration = Duration::from_secs(24 * 60 * 60);

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
struct AccessToken(pub String);

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
struct RefreshToken(pub String);

#[derive(Clone)]
struct AppState {
    logins_by_access_token: Arc<Mutex<BTreeMap<AccessToken, LoginInfo>>>,
    access_tokens_by_refresh_token: Arc<Mutex<BTreeMap<RefreshToken, AccessToken>>>,
}

impl AppState {
    fn new() -> Self {
        Self {
            logins_by_access_token: Arc::new(Mutex::new(BTreeMap::new())),
            access_tokens_by_refresh_token: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    fn login(
        &mut self,
        loginname: impl Into<String>,
        _password: impl Into<String>,
    ) -> Option<(AccessTokenResponse, RefreshTokenResponse, LoginInfo)> {
        let access_token = AccessToken(Uuid::new_v4().as_hyphenated().to_string());
        let refresh_token = RefreshToken(Uuid::new_v4().as_hyphenated().to_string());

        let loginname = loginname.into();
        let login_info = LoginInfo { loginname };

        self.logins_by_access_token
            .lock()
            .insert(access_token.clone(), login_info.clone());

        self.access_tokens_by_refresh_token
            .lock()
            .insert(refresh_token.clone(), access_token.clone());

        Some((
            AccessTokenResponse::with_time_delta(
                access_token.0,
                ACCESS_TOKEN_EXPIRATION_TIME_DURATION,
                None,
            ),
            RefreshTokenResponse::with_time_delta(
                refresh_token.0,
                REFRESH_TOKEN_EXPIRATION_TIME_DURATION,
                "/api/refresh-login",
            ),
            login_info,
        ))
    }

    fn refresh(&mut self, refresh_token: impl Into<String>) -> Option<AccessTokenResponse> {
        let refresh_token = RefreshToken(refresh_token.into());

        let access_token = self
            .access_tokens_by_refresh_token
            .lock()
            .remove(&refresh_token)?;

        let login_info = self.logins_by_access_token.lock().remove(&access_token)?;

        let new_access_token = AccessToken(Uuid::new_v4().as_hyphenated().to_string());

        self.logins_by_access_token
            .lock()
            .insert(new_access_token.clone(), login_info);
        self.access_tokens_by_refresh_token
            .lock()
            .insert(refresh_token, new_access_token.clone());

        Some(AccessTokenResponse::with_time_delta(
            new_access_token.0,
            REFRESH_TOKEN_EXPIRATION_TIME_DURATION,
            None,
        ))
    }

    fn logout(&mut self, refresh_token: impl AsRef<str>) {
        if let Some(access_token) = self
            .access_tokens_by_refresh_token
            .lock()
            .remove(&RefreshToken(refresh_token.as_ref().into()))
        {
            if let Some(login_info) = self.logins_by_access_token.lock().remove(&access_token) {
                log::info!("User logged out, loginname = '{}'", login_info.loginname);
            }
        }

        log::info!(
            "Refresh token revoked, refresh_token = {}",
            refresh_token.as_ref()
        );
    }
}

#[async_trait]
impl AuthHandler<LoginInfo> for AppState {
    async fn verify_access_token(&mut self, access_token: &str) -> Result<LoginInfo, StatusCode> {
        self.logins_by_access_token
            .lock()
            .get(&AccessToken(access_token.into()))
            .cloned()
            .ok_or_else(|| StatusCode::BAD_REQUEST)
    }

    async fn update_access_token(
        &mut self,
        access_token: &str,
        _login_info: &Arc<LoginInfo>,
    ) -> Option<(String, Duration)> {
        Some((access_token.into(), ACCESS_TOKEN_EXPIRATION_TIME_DURATION))
    }

    async fn revoke_access_token(&mut self, access_token: &str, login_info: &Arc<LoginInfo>) {
        self.logins_by_access_token
            .lock()
            .remove(&AccessToken(access_token.into()));

        log::info!(
            "Access token of user revoked, loginname = '{}'",
            login_info.loginname
        );
    }

    async fn verify_refresh_token(&mut self, refresh_token: &str) -> Result<(), StatusCode> {
        self.access_tokens_by_refresh_token
            .lock()
            .contains_key(&RefreshToken(refresh_token.into()))
            .then_some(())
            .ok_or_else(|| StatusCode::BAD_REQUEST)
    }

    async fn revoke_refresh_token(&mut self, refresh_token: &str) {
        self.logout(refresh_token);
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
            .route("/api/refresh-login", post(api_refresh_login))
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
) -> Result<
    (
        StatusCode,
        AccessTokenResponse,
        RefreshTokenResponse,
        Json<LoginResponse>,
    ),
    StatusCode,
> {
    let (access_token, refresh_token, _login_info) = state
        .login(&login_request.loginname, login_request.password)
        .ok_or_else(|| StatusCode::BAD_REQUEST)?;

    log::info!("User logged in, loginname = '{}'", login_request.loginname);

    Ok((
        StatusCode::OK,
        access_token,
        refresh_token,
        Json(LoginResponse {
            loginname: login_request.loginname,
        }),
    ))
}

async fn api_refresh_login(
    RefreshTokenExtractor(refresh_token): RefreshTokenExtractor,
    State(mut state): State<AppState>,
) -> Result<(StatusCode, AccessTokenResponse), StatusCode> {
    let access_token = state
        .refresh(refresh_token)
        .ok_or_else(|| StatusCode::BAD_REQUEST)?;

    Ok((StatusCode::OK, access_token))
}

async fn api_logout(
    RefreshTokenExtractor(refresh_token): RefreshTokenExtractor,
    State(mut state): State<AppState>,
) -> Result<AuthLogoutResponse, StatusCode> {
    state.logout(refresh_token);
    Ok(AuthLogoutResponse::new(Some("/"), Some("/")))
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
async fn expired_access_token() {
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
    response.assert_status_ok();
    response.assert_text("private");

    std::thread::sleep(Duration::from_secs(1));

    let response = server.get("/private").await;
    response.assert_status_unauthorized();

    // even the second request should fail (access token should not be renewed at first call)
    let response = server.get("/private").await;
    response.assert_status_unauthorized();

    let response = server.post("/api/refresh-login").await;
    response.assert_status_ok();

    let response = server.get("/private").await;
    response.assert_status_ok();
    response.assert_text("private");
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
