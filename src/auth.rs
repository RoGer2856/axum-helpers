use std::{
    future::Future,
    marker::PhantomData,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use async_trait::async_trait;
use axum::{
    extract::FromRequestParts,
    http::{Request, StatusCode},
    response::{IntoResponse, IntoResponseParts, Response, ResponseParts},
};
use axum_extra::extract::{
    cookie::{Cookie, SameSite},
    CookieJar,
};
use http_body::Body;
use time::OffsetDateTime;
use tower::{Layer, Service};

const ACCESS_TOKEN_COOKIE_NAME: &str = "access_token";

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
            .get::<Arc<LoginInfoType>>()
            .map(|login_info| LoginInfoExtractor(login_info.clone()))
            .ok_or(StatusCode::UNAUTHORIZED);

        Box::pin(async move { login_info })
    }
}

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

pub fn is_cookie_expired_by_date(cookie: &Cookie) -> bool {
    if let Some(date_time) = cookie.expires_datetime() {
        let now = std::time::SystemTime::now();
        return date_time < now;
    }

    false
}

fn create_auth_cookie<'a>(
    access_token: impl Into<String>,
    expires_at: OffsetDateTime,
    path: impl Into<String>,
) -> Cookie<'a> {
    Cookie::build((ACCESS_TOKEN_COOKIE_NAME, access_token.into()))
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Strict)
        .expires(expires_at)
        .path(path.into())
        .build()
}

#[derive(Clone)]
pub struct AuthLayer<
    LoginInfoType: Clone + Send + Sync + 'static,
    AuthHandlerType: AuthHandler<LoginInfoType>,
> {
    _marker: PhantomData<LoginInfoType>,

    auth_impl: AuthHandlerType,
}

impl<LoginInfoType: Clone + Send + Sync + 'static, AuthHandlerType: AuthHandler<LoginInfoType>>
    AuthLayer<LoginInfoType, AuthHandlerType>
{
    pub fn new(auth_impl: AuthHandlerType) -> Self {
        Self {
            _marker: PhantomData,

            auth_impl,
        }
    }
}

impl<
        ServiceType,
        LoginInfoType: Clone + Send + Sync + 'static,
        AuthHandlerType: AuthHandler<LoginInfoType>,
    > Layer<ServiceType> for AuthLayer<LoginInfoType, AuthHandlerType>
{
    type Service = AuthMiddleware<ServiceType, LoginInfoType, AuthHandlerType>;

    fn layer(&self, inner: ServiceType) -> Self::Service {
        AuthMiddleware {
            _marker: PhantomData,

            inner,
            auth_impl: self.auth_impl.clone(),
        }
    }
}

#[derive(Clone)]
pub struct AuthMiddleware<
    ServiceType,
    LoginInfoType: Clone + Send + Sync + 'static,
    AuthHandlerType: AuthHandler<LoginInfoType>,
> {
    _marker: PhantomData<LoginInfoType>,

    inner: ServiceType,
    auth_impl: AuthHandlerType,
}

impl<ServiceType, RequestBodyType, ResponseType, LoginInfoType, AuthHandlerType>
    Service<Request<RequestBodyType>>
    for AuthMiddleware<ServiceType, LoginInfoType, AuthHandlerType>
where
    LoginInfoType: Clone + Send + Sync + 'static,
    AuthHandlerType: AuthHandler<LoginInfoType>,
    ServiceType: Service<Request<RequestBodyType>> + Clone + Send + 'static,
    ServiceType::Future: Future<Output = Result<ResponseType, ServiceType::Error>> + Send,
    ServiceType::Error: Send,
    ResponseType: IntoResponse + Send,
    RequestBodyType: Body + Send + 'static,
{
    type Response = Response;
    type Error = ServiceType::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Response, ServiceType::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<RequestBodyType>) -> Self::Future {
        let mut auth_impl = self.auth_impl.clone();
        let mut inner = self.inner.clone();
        Box::pin(async move {
            let mut access_token_login_info_pair = None;
            let cookie_jar = CookieJar::from_headers(req.headers());
            for cookie in cookie_jar.iter() {
                if cookie.name() == ACCESS_TOKEN_COOKIE_NAME && !is_cookie_expired_by_date(cookie) {
                    let at = cookie.value().to_string();
                    if let Ok(li) = auth_impl.verify_access_token(&at).await {
                        access_token_login_info_pair = Some((at, Arc::new(li)));

                        break;
                    }
                }
            }

            if let Some((_at, login_info)) = &access_token_login_info_pair {
                req.extensions_mut().insert(login_info.clone());
            }

            let next_response = inner.call(req).await;

            match next_response {
                Ok(next_response) => {
                    let mut response = next_response.into_response();

                    let cookie_jar = CookieJar::new();
                    let cookie_jar =
                        if let Some((access_token, login_info)) = &access_token_login_info_pair {
                            if let Some(_auth_logout_response) =
                                response.extensions_mut().remove::<AuthLogoutResponse>()
                            {
                                auth_impl
                                    .invalidate_access_token(access_token, login_info)
                                    .await;
                                cookie_jar.add(create_auth_cookie(
                                    access_token,
                                    time::OffsetDateTime::UNIX_EPOCH,
                                    "/",
                                ))
                            } else if let Ok((access_token, expiration_time_delta)) = auth_impl
                                .update_access_token(access_token, login_info)
                                .await
                            {
                                cookie_jar.add(create_auth_cookie(
                                    access_token,
                                    time::OffsetDateTime::now_utc() + expiration_time_delta,
                                    "/",
                                ))
                            } else {
                                cookie_jar
                            }
                        } else {
                            cookie_jar
                        };

                    response.headers_mut().extend(
                        cookie_jar.into_response().headers().into_iter().map(
                            |(header_name, header_value)| {
                                (header_name.clone(), header_value.clone())
                            },
                        ),
                    );

                    Ok(response)
                }
                Err(e) => Err(e),
            }
        })
    }
}

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
