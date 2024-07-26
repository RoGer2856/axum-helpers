use axum::response::{IntoResponse, IntoResponseParts, Response, ResponseParts};

#[derive(Clone)]
pub struct AuthLogoutResponse;

impl IntoResponseParts for AuthLogoutResponse {
    type Error = ();

    fn into_response_parts(self, mut res: ResponseParts) -> Result<ResponseParts, Self::Error> {
        res.extensions_mut().insert(self);

        Ok(res)
    }
}

impl IntoResponse for AuthLogoutResponse {
    fn into_response(self) -> Response {
        (self, ()).into_response()
    }
}
