use std::{borrow::Borrow, ops::Deref, sync::Arc};

use async_trait::async_trait;
use axum::http::StatusCode;
use tokio::time::Duration;

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct AccessToken(pub(super) String);

impl AccessToken {
    pub fn new(token: String) -> Self {
        Self(token)
    }
}

impl Deref for AccessToken {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Borrow<str> for AccessToken {
    fn borrow(&self) -> &str {
        &self.0
    }
}

impl Borrow<String> for AccessToken {
    fn borrow(&self) -> &String {
        &self.0
    }
}

impl From<AccessToken> for String {
    fn from(token: AccessToken) -> Self {
        token.0
    }
}

impl AsRef<str> for AccessToken {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct RefreshToken(pub(super) String);

impl RefreshToken {
    pub fn new(token: String) -> Self {
        Self(token)
    }
}

impl Deref for RefreshToken {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Borrow<str> for RefreshToken {
    fn borrow(&self) -> &str {
        &self.0
    }
}

impl Borrow<String> for RefreshToken {
    fn borrow(&self) -> &String {
        &self.0
    }
}

impl From<RefreshToken> for String {
    fn from(token: RefreshToken) -> Self {
        token.0
    }
}

impl AsRef<str> for RefreshToken {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[async_trait]
pub trait AuthHandler<LoginInfoType: Send + Sync>: Sized + Clone + Send + Sync + 'static {
    /// Update access token is called for every request that contains a access token
    async fn verify_access_token(
        &mut self,
        access_token: &AccessToken,
    ) -> Result<LoginInfoType, StatusCode>;

    /// Update access token is called for every request that contains a valid access token.
    /// The returned access token is sent for the client.
    async fn update_access_token(
        &mut self,
        access_token: &AccessToken,
        login_info: &Arc<LoginInfoType>,
    ) -> Option<(AccessToken, Duration)>;

    /// Revoke access token is called when the auth layer receives a logout response from a request handler.
    async fn revoke_access_token(
        &mut self,
        access_token: &AccessToken,
        login_info: &Arc<LoginInfoType>,
    );

    /// Verify refresh token is called for every request that contains a refresh token.
    async fn verify_refresh_token(
        &mut self,
        refresh_token: &RefreshToken,
    ) -> Result<(), StatusCode>;

    /// Revoke refresh token is called when the auth layer receives a logout response from a request handler.
    async fn revoke_refresh_token(&mut self, refresh_token: &RefreshToken);
}
