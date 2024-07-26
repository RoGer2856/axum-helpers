use axum::response::{IntoResponse, IntoResponseParts, Response, ResponseParts};
use axum_extra::extract::CookieJar;
use time::OffsetDateTime;
use tokio::time::Duration;

use super::auth_layer::create_auth_cookie;

pub struct AuthLoginResponse {
    access_token: String,
    expires_at: OffsetDateTime,
}

impl AuthLoginResponse {
    pub fn new(access_token: String, expiration_time_delta: Duration) -> Self {
        Self {
            access_token,
            expires_at: OffsetDateTime::now_utc() + expiration_time_delta,
        }
    }
}

impl IntoResponseParts for AuthLoginResponse {
    type Error = <CookieJar as IntoResponseParts>::Error;

    fn into_response_parts(
        self,
        res: axum::response::ResponseParts,
    ) -> Result<ResponseParts, Self::Error> {
        let cookie = create_auth_cookie(self.access_token, self.expires_at, "/");

        CookieJar::new().add(cookie).into_response_parts(res)
    }
}

impl IntoResponse for AuthLoginResponse {
    fn into_response(self) -> Response {
        (self, ()).into_response()
    }
}
