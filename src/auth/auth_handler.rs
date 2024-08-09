use std::sync::Arc;

use async_trait::async_trait;
use axum::http::StatusCode;
use tokio::time::Duration;

#[async_trait]
pub trait AuthHandler<LoginInfoType: Send + Sync>: Sized + Clone + Send + Sync + 'static {
    /// Update access token is called for every request that contains a access token
    async fn verify_access_token(
        &mut self,
        access_token: &str,
    ) -> Result<LoginInfoType, StatusCode>;

    /// Update access token is called for every request that contains a valid access token.
    /// The returned access token is sent for the client.
    async fn update_access_token(
        &mut self,
        access_token: &str,
        login_info: &Arc<LoginInfoType>,
    ) -> Option<(String, Duration)>;

    /// Revoke access token is called when the auth layer receives a logout response from a request handler.
    async fn revoke_access_token(&mut self, access_token: &str, login_info: &Arc<LoginInfoType>);

    /// Verify refresh token is called for every request that contains a refresh token.
    async fn verify_refresh_token(&mut self, refresh_token: &str) -> Result<(), StatusCode>;

    /// Revoke refresh token is called when the auth layer receives a logout response from a request handler.
    async fn revoke_refresh_token(&mut self, refresh_token: &str);
}
