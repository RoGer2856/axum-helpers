use axum::response::{IntoResponse, IntoResponseParts, Response, ResponseParts};

use super::auth_layer::AuthLogoutExtension;

#[derive(Clone)]
pub struct AuthLogoutResponse {
    pub(super) access_token_path: Option<String>,
    pub(super) refresh_token_path: Option<String>,
}

impl AuthLogoutResponse {
    pub fn new(
        access_token_path: Option<impl Into<String>>,
        refresh_token_path: Option<impl Into<String>>,
    ) -> Self {
        Self {
            access_token_path: access_token_path.map(|path| path.into()),
            refresh_token_path: refresh_token_path.map(|path| path.into()),
        }
    }
}

impl IntoResponseParts for AuthLogoutResponse {
    type Error = ();

    fn into_response_parts(self, mut res: ResponseParts) -> Result<ResponseParts, Self::Error> {
        res.extensions_mut().insert(AuthLogoutExtension(self));

        Ok(res)
    }
}

impl IntoResponse for AuthLogoutResponse {
    fn into_response(self) -> Response {
        (self, ()).into_response()
    }
}
