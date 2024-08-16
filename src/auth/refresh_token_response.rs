use std::convert::Infallible;

use axum::response::{IntoResponse, IntoResponseParts, Response, ResponseParts};
use time::OffsetDateTime;
use tokio::time::Duration;

use super::{token_response::TokenResponse, RefreshToken};

#[derive(Debug, Clone)]
pub struct RefreshTokenResponse(pub(super) TokenResponse<RefreshToken>);

impl RefreshTokenResponse {
    pub fn with_offset_date_time(
        token: impl Into<RefreshToken>,
        expires_at: OffsetDateTime,
        path: &str,
    ) -> Self {
        Self(TokenResponse::with_offset_date_time(
            token,
            expires_at,
            Some(path),
        ))
    }

    pub fn with_time_delta(
        token: impl Into<RefreshToken>,
        expiration_time_delta: Duration,
        path: &str,
    ) -> Self {
        Self(TokenResponse::with_time_delta(
            token.into(),
            expiration_time_delta,
            Some(path),
        ))
    }

    pub fn token(&self) -> &RefreshToken {
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
    type Error = Infallible;

    fn into_response_parts(
        self,
        mut res: axum::response::ResponseParts,
    ) -> Result<ResponseParts, Self::Error> {
        res.extensions_mut().insert(self);
        Ok(res)
    }
}

impl IntoResponse for RefreshTokenResponse {
    fn into_response(self) -> Response {
        (self, ()).into_response()
    }
}
