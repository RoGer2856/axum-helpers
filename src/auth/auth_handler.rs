use std::sync::Arc;

use async_trait::async_trait;
use tokio::time::Duration;

use super::AuthError;

#[async_trait]
pub trait AuthHandler<LoginInfoType: Clone + Send + Sync>:
    Sized + Clone + Send + Sync + 'static
{
    async fn verify_access_token(&mut self, access_token: &str)
        -> Result<LoginInfoType, AuthError>;
    async fn update_access_token(
        &mut self,
        access_token: &str,
        login_info: &Arc<LoginInfoType>,
    ) -> Result<(String, Duration), AuthError>;
    async fn invalidate_access_token(
        &mut self,
        access_token: &str,
        login_info: &Arc<LoginInfoType>,
    );
}
