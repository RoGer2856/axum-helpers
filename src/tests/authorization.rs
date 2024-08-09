use std::{collections::BTreeMap, future::Future, sync::Arc, time::Duration};

use async_trait::async_trait;
use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};

use crate::{
    app::{AxumApp, AxumAppState},
    auth::{AccessTokenResponse, AuthHandler, AuthLayer, AuthLogoutResponse, LoginInfoExtractor},
};
use parking_lot::Mutex;
use uuid::Uuid;

const ACCESS_TOKEN_EXPIRATION_TIME_DURATION: Duration = Duration::from_secs(5 * 60 * 60 * 24);

#[derive(Clone)]
struct AppState {
    logins: Arc<Mutex<BTreeMap<AccessToken, LoginInfo>>>,
}

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
struct AccessToken(pub String);

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
    ) -> Option<(AccessTokenResponse, LoginInfo)> {
        let access_token_response = AccessTokenResponse::with_time_delta(
            Uuid::new_v4().as_hyphenated().to_string(),
            ACCESS_TOKEN_EXPIRATION_TIME_DURATION,
            None,
        );
        let loginname = loginname.into();

        let role = match loginname.as_str() {
            "admin" => "admin",
            _ => "regular",
        }
        .into();

        let login_info = LoginInfo { loginname, role };

        self.logins.lock().insert(
            AccessToken(access_token_response.token().into()),
            login_info.clone(),
        );

        Some((access_token_response, login_info))
    }

    fn logout(&mut self, access_token: impl Into<String>, login_info: &Arc<LoginInfo>) {
        self.logins.lock().remove(&AccessToken(access_token.into()));

        log::info!("User logged out, loginname = '{}'", login_info.loginname);
    }
}

#[async_trait]
impl AuthHandler<LoginInfo> for AppState {
    async fn verify_access_token(&mut self, access_token: &str) -> Result<LoginInfo, StatusCode> {
        self.logins
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
        self.logout(access_token, login_info);
    }

    async fn verify_refresh_token(&mut self, _refresh_token: &str) -> Result<(), StatusCode> {
        unreachable!("tests contained in this file, this line should not be called")
    }

    async fn revoke_refresh_token(&mut self, _refresh_token: &str) {
        unreachable!("tests contained in this file, this line should not be called")
    }
}

impl AxumAppState for AppState {
    fn routes(&self) -> Router {
        Router::new()
            .route("/admin-page", get(get_admin_page))
            .route("/api/login", post(api_login))
            .route("/api/logout", post(api_logout))
            .route_layer(AuthLayer::new(self.clone()))
            .with_state(self.clone())
    }
}

async fn check_required_role<FutureType: Future<Output = impl IntoResponse>>(
    required_role: &str,
    f: impl FnOnce(LoginInfoExtractor<LoginInfo>) -> FutureType,
    LoginInfoExtractor(login_info): LoginInfoExtractor<LoginInfo>,
) -> Result<impl IntoResponse, StatusCode> {
    if login_info.role == required_role {
        Ok(f(LoginInfoExtractor(login_info)).await)
    } else {
        Err(StatusCode::FORBIDDEN)
    }
}

#[fn_decorator::use_decorator(check_required_role("admin"), override_return_type = impl IntoResponse, exact_parameters = [_login_info])]
async fn get_admin_page(_login_info: LoginInfoExtractor<LoginInfo>) -> &'static str {
    "admin-page"
}

#[derive(Clone)]
struct LoginInfo {
    loginname: String,
    role: String,
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
) -> Result<(StatusCode, AccessTokenResponse, Json<LoginResponse>), StatusCode> {
    let (access_token_response, _login_info) = state
        .login(&login_request.loginname, login_request.password)
        .ok_or_else(|| StatusCode::BAD_REQUEST)?;

    log::info!("User logged in, loginname = '{}'", login_request.loginname);

    Ok((
        StatusCode::OK,
        access_token_response,
        Json(LoginResponse {
            loginname: login_request.loginname,
        }),
    ))
}

async fn api_logout(
    LoginInfoExtractor(_login_info): LoginInfoExtractor<LoginInfo>,
) -> Result<AuthLogoutResponse, StatusCode> {
    Ok(AuthLogoutResponse::new(Some("/"), Some("/")))
}

#[tokio::test]
async fn get_page_with_access_policy() {
    let app = AxumApp::new(AppState::new());
    let mut server = app.spawn_test_server().unwrap();
    server.do_save_cookies();

    server
        .post("/api/login")
        .json(&LoginRequest {
            loginname: "admin".into(),
            password: "password".into(),
        })
        .await;

    let response = server.get("/admin-page").await;
    response.assert_status_ok();
    response.assert_text("admin-page");
}

#[tokio::test]
async fn get_page_with_incorrect_access_policy() {
    let app = AxumApp::new(AppState::new());
    let mut server = app.spawn_test_server().unwrap();
    server.do_save_cookies();

    server
        .post("/api/login")
        .json(&LoginRequest {
            loginname: "roger".into(),
            password: "password".into(),
        })
        .await;

    let response = server.get("/admin-page").await;
    response.assert_status_forbidden();
}
