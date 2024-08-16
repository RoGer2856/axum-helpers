use time::OffsetDateTime;
use tokio::time::Duration;

#[derive(Debug, Clone)]
pub(super) struct TokenResponse<TokenType> {
    pub(super) token: TokenType,
    pub(super) expires_at: OffsetDateTime,
    pub(super) path: String,
}

impl<TokenType> TokenResponse<TokenType> {
    pub(super) fn with_offset_date_time(
        token: impl Into<TokenType>,
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

    pub(super) fn with_time_delta(
        token: impl Into<TokenType>,
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
