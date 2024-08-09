use axum::response::{IntoResponse, IntoResponseParts, Response, ResponseParts};
use axum_extra::extract::CookieJar;
use time::OffsetDateTime;
use tokio::time::Duration;

use super::auth_layer::{create_access_token_cookie, create_refresh_token_cookie};

#[derive(Debug, Clone)]
pub struct AccessTokenResponse(pub(super) TokenResponse);

#[derive(Debug, Clone)]
pub struct RefreshTokenResponse(pub(super) TokenResponse);

#[derive(Debug, Clone)]
pub struct TokenResponse {
    pub(super) token: String,
    pub(super) expires_at: OffsetDateTime,
    pub(super) path: String,
}

impl TokenResponse {
    fn with_offset_date_time(
        token: impl Into<String>,
        expires_at: OffsetDateTime,
        path: Option<impl Into<String>>,
    ) -> Self {
        Self {
            token: token.into(),
            expires_at,
            path: path
                .map(|path| path.into())
                .unwrap_or_else(|| "/".to_string()),
        }
    }

    fn with_time_delta(
        token: impl Into<String>,
        expiration_time_delta: Duration,
        path: Option<impl Into<String>>,
    ) -> Self {
        Self::with_offset_date_time(
            token,
            OffsetDateTime::now_utc() + expiration_time_delta,
            path,
        )
    }
}

impl AccessTokenResponse {
    pub fn with_offset_date_time(
        token: impl Into<String>,
        expires_at: OffsetDateTime,
        path: Option<&str>,
    ) -> Self {
        Self(TokenResponse::with_offset_date_time(
            token, expires_at, path,
        ))
    }

    pub fn with_time_delta(
        token: impl Into<String>,
        expiration_time_delta: Duration,
        path: Option<&str>,
    ) -> Self {
        Self(TokenResponse::with_time_delta(
            token,
            expiration_time_delta,
            path,
        ))
    }

    pub fn token(&self) -> &str {
        &self.0.token
    }

    pub fn expires_at(&self) -> &OffsetDateTime {
        &self.0.expires_at
    }

    pub fn path(&self) -> &str {
        &self.0.path
    }
}

impl IntoResponseParts for AccessTokenResponse {
    type Error = <CookieJar as IntoResponseParts>::Error;

    fn into_response_parts(
        self,
        res: axum::response::ResponseParts,
    ) -> Result<ResponseParts, Self::Error> {
        let cookie = create_access_token_cookie(self.0.token, self.0.expires_at, self.0.path);

        CookieJar::new().add(cookie).into_response_parts(res)
    }
}

impl IntoResponse for AccessTokenResponse {
    fn into_response(self) -> Response {
        (self, ()).into_response()
    }
}

impl RefreshTokenResponse {
    pub fn with_offset_date_time(token: String, expires_at: OffsetDateTime, path: &str) -> Self {
        Self(TokenResponse::with_offset_date_time(
            token,
            expires_at,
            Some(path),
        ))
    }

    pub fn with_time_delta(token: String, expiration_time_delta: Duration, path: &str) -> Self {
        Self(TokenResponse::with_time_delta(
            token,
            expiration_time_delta,
            Some(path),
        ))
    }

    pub fn token(&self) -> &str {
        &self.0.token
    }

    pub fn expires_at(&self) -> &OffsetDateTime {
        &self.0.expires_at
    }

    pub fn path(&self) -> &str {
        &self.0.path
    }
}

impl IntoResponseParts for RefreshTokenResponse {
    type Error = <CookieJar as IntoResponseParts>::Error;

    fn into_response_parts(
        self,
        res: axum::response::ResponseParts,
    ) -> Result<ResponseParts, Self::Error> {
        let cookie = create_refresh_token_cookie(self.0.token, self.0.expires_at, self.0.path);

        CookieJar::new().add(cookie).into_response_parts(res)
    }
}

impl IntoResponse for RefreshTokenResponse {
    fn into_response(self) -> Response {
        (self, ()).into_response()
    }
}
