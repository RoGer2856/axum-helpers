use std::{collections::BTreeMap, net::ToSocketAddrs, sync::Arc, time::Duration};

use async_trait::async_trait;
use axum::{
    extract::State,
    http::StatusCode,
    response::Html,
    routing::{get, post},
    Json, Router,
};
use axum_helpers::{
    app::{AxumApp, AxumAppState},
    auth::{
        AuthError, AuthHandler, AuthLayer, AuthLoginResponse, AuthLogoutResponse,
        LoginInfoExtractor,
    },
};
use clap::Parser;
use parking_lot::Mutex;
use tracing_subscriber::{prelude::__tracing_subscriber_SubscriberExt, util::SubscriberInitExt};
use uuid::Uuid;

const ACCESS_TOKEN_EXPIRATION_TIME_DURATION: Duration = Duration::from_secs(5 * 60 * 60 * 24);

#[derive(Parser)]
#[command()]
pub struct Cli {
    #[arg(
        short('l'),
        long("listener-address"),
        help("Address where the server accepts the connections (e.g., 127.0.0.1)")
    )]
    listener_address: String,
}

#[derive(Clone)]
struct AppState {
    logins: Arc<Mutex<BTreeMap<AccessToken, String>>>,
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
    ) -> (AccessToken, LoginInfo) {
        let access_token = AccessToken(Uuid::new_v4().as_hyphenated().to_string());
        let loginname = loginname.into();

        self.logins
            .lock()
            .insert(access_token.clone(), loginname.clone());

        (access_token, LoginInfo { loginname })
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
            .map(|loginname| LoginInfo {
                loginname: loginname.clone(),
            })
            .ok_or_else(|| AuthError::InvalidAccessToken)
    }

    async fn update_access_token(
        &mut self,
        access_token: &str,
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
            .route("/", get(index_page))
            .route("/login", get(login_page))
            .route("/api/login", post(api_login))
            .route("/api/logout", post(api_logout))
            .route_layer(AuthLayer::new(self.clone()))
            .with_state(self.clone())
    }
}

async fn index_page(login_info: Option<LoginInfoExtractor<LoginInfo>>) -> Html<String> {
    let header = if login_info.is_some() {
        r#"
            <script>
                async function logout(event) {
                    event.preventDefault();

                    await fetch("/api/logout", {
                        method: "POST",
                    });

                    location.reload();
                }
            </script>
            <form onsubmit="logout(event)">
                <button>Logout</button>
            </form>
        "#
    } else {
        r#"
            <div><a href="/login">Login</a></div>
        "#
    };

    Html(format!(
        r#"
            <html>
                <body>
                    {header}
                    <h1>Endpoints</h1>
                    <ul>
                        <li><b>get /</b>: returns this page</li>
                        <li><b>get /login</b>: returns a page where a user can log in</li>

                        <li><b>post /api/login</b>: logs a user in</li>
                        <li><b>post /api/logout</b>: logs a user out</li>
                    </ul>
                </body>
            </html>
        "#
    ))
}

async fn login_page(login_info: Option<LoginInfoExtractor<LoginInfo>>) -> Html<String> {
    let body_content = if login_info.is_some() {
        r#"
            You are already logged in!
        "#
    } else {
        r#"
            <script>
                async function login(event) {
                    event.preventDefault();

                    let loginname = document.getElementById("loginname").value;
                    let password = document.getElementById("password").value;

                    await fetch("/api/login", {
                        method: "POST",
                        headers: {
                            'Content-Type': 'application/json',
                        },
                        body: JSON.stringify({
                            loginname,
                            password,
                        }),
                    });

                    location = "/";
                }
            </script>
            <h1>Login</h1>
            <form onsubmit="login(event)">
                <label for="loginname">Loginname</label>
                <input type="username" id="loginname" />

                <label for="password">Password</label>
                <input type="password" id="password" />

                <button>Login</button>
            </form>
        "#
    };

    Html(format!(
        r#"
            <html>
                <body>
                    {body_content}
                </body>
            </html>
        "#
    ))
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
        AuthLoginResponse::new(access_token.0, ACCESS_TOKEN_EXPIRATION_TIME_DURATION),
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

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                "app_with_auth=debug,axum_helpers=debug,tower_http=debug".into()
            }),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let cli = Cli::parse();

    let mut app = AxumApp::new(AppState::new());
    for addr in cli.listener_address.to_socket_addrs().unwrap() {
        let _ = app.spawn_server(addr).await;
    }

    app.join().await;
}
