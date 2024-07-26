use axum::http::StatusCode;

#[derive(Debug, Clone)]
pub enum AuthError {
    Internal,
    NoSuchUser,
    InvalidPassword,
    InvalidAccessToken,
    UserNotLoggedIn,
}

impl std::convert::From<AuthError> for StatusCode {
    fn from(value: AuthError) -> Self {
        match value {
            AuthError::Internal => StatusCode::INTERNAL_SERVER_ERROR,
            AuthError::InvalidPassword => StatusCode::BAD_REQUEST,
            AuthError::NoSuchUser => StatusCode::BAD_REQUEST,
            AuthError::InvalidAccessToken => StatusCode::BAD_REQUEST,
            AuthError::UserNotLoggedIn => StatusCode::BAD_REQUEST,
        }
    }
}
