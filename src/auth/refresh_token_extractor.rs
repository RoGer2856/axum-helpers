use std::{future::Future, pin::Pin};

use axum::{extract::FromRequestParts, http::StatusCode};

use super::auth_layer::RefreshTokenVerificationResultExtension;

pub struct RefreshTokenExtractor(pub String);

impl<StateType> FromRequestParts<StateType> for RefreshTokenExtractor {
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
        let refresh_token = parts
            .extensions
            .get::<RefreshTokenVerificationResultExtension>()
            .ok_or(StatusCode::UNAUTHORIZED)
            .and_then(|refresh_token_verification_result_extension| {
                if let Err(status_code) = refresh_token_verification_result_extension.0 .1 {
                    Err(status_code)
                } else {
                    Ok(RefreshTokenExtractor(
                        refresh_token_verification_result_extension.0 .0.clone(),
                    ))
                }
            });

        Box::pin(async move { refresh_token })
    }
}
