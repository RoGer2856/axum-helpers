use time::OffsetDateTime;
use tokio::time::Duration;

#[derive(Debug, Clone)]
pub struct AccessTokenInfo(pub(super) TokenInfo);

#[derive(Debug, Clone)]
pub struct TokenInfo {
    pub(super) token: String,
    pub(super) expires_at: OffsetDateTime,
    pub(super) path: String,
}

impl TokenInfo {
    fn with_offset_date_time(
        token: String,
        expires_at: OffsetDateTime,
        path: Option<impl Into<String>>,
    ) -> Self {
        Self {
            token,
            expires_at,
            path: path
                .map(|path| path.into())
                .unwrap_or_else(|| "/".to_string()),
        }
    }

    fn with_time_delta(
        token: String,
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

impl AccessTokenInfo {
    pub fn with_offset_date_time(
        token: String,
        expires_at: OffsetDateTime,
        path: Option<&str>,
    ) -> Self {
        Self(TokenInfo::with_offset_date_time(token, expires_at, path))
    }

    pub fn with_time_delta(
        token: String,
        expiration_time_delta: Duration,
        path: Option<&str>,
    ) -> Self {
        Self(TokenInfo::with_time_delta(
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
