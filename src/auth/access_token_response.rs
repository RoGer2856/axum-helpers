use std::convert::Infallible;

use axum::response::{IntoResponse, IntoResponseParts, Response, ResponseParts};
use time::OffsetDateTime;
use tokio::time::Duration;

use super::{token_response::TokenResponse, AccessToken};

#[derive(Debug, Clone)]
pub struct AccessTokenResponse(pub(super) TokenResponse<AccessToken>);

impl AccessTokenResponse {
    pub fn with_offset_date_time(
        token: impl Into<AccessToken>,
        expires_at: OffsetDateTime,
        path: Option<&str>,
    ) -> Self {
        Self(TokenResponse::with_offset_date_time(
            token, expires_at, path,
        ))
    }

    pub fn with_time_delta(
        token: impl Into<AccessToken>,
        expiration_time_delta: Duration,
        path: Option<&str>,
    ) -> Self {
        Self(TokenResponse::with_time_delta(
            token.into(),
            expiration_time_delta,
            path,
        ))
    }

    pub fn token(&self) -> &AccessToken {
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
    type Error = Infallible;

    fn into_response_parts(
        self,
        mut res: axum::response::ResponseParts,
    ) -> Result<ResponseParts, Self::Error> {
        res.extensions_mut().insert(self);
        Ok(res)
    }
}

impl IntoResponse for AccessTokenResponse {
    fn into_response(self) -> Response {
        (self, ()).into_response()
    }
}
