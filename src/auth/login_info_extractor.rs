use std::{future::Future, pin::Pin, sync::Arc};

use axum::{extract::FromRequestParts, http::StatusCode};

use super::auth_layer::AccessTokenVerificationResultExtension;

pub struct LoginInfoExtractor<LoginInfoType: Clone + Send + Sync + 'static>(pub Arc<LoginInfoType>);

impl<StateType, LoginInfoType> FromRequestParts<StateType> for LoginInfoExtractor<LoginInfoType>
where
    LoginInfoType: Clone + Send + Sync + 'static,
{
    type Rejection = StatusCode;

    fn from_request_parts<'life0, 'life1, 'async_trait>(
        parts: &'life0 mut axum::http::request::Parts,
        _state: &'life1 StateType,
    ) -> Pin<Box<dyn Future<Output = Result<Self, Self::Rejection>> + Send + 'async_trait>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        let login_info = parts
            .extensions
            .get::<AccessTokenVerificationResultExtension<LoginInfoType>>()
            .ok_or(StatusCode::UNAUTHORIZED)
            .and_then(|access_token_verification_result_extension| {
                Ok(LoginInfoExtractor(
                    access_token_verification_result_extension
                        .0
                        .as_ref()?
                        .clone(),
                ))
            });

        Box::pin(async move { login_info })
    }
}
