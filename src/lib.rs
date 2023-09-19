use std::{
    future::Future,
    marker::PhantomData,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use axum::{
    extract::FromRequestParts,
    http::{Request, StatusCode},
    response::{IntoResponse, Response},
};
use axum_extra::extract::{cookie::Cookie, CookieJar};
use http_body::Body;
use pin_project::pin_project;
use tower::{Layer, Service};

const ACCESS_TOKEN_COOKIE_NAME: &'static str = "access_token";

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

pub struct LoginInfoExtractor<LoginInfoType>(pub LoginInfoType);

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
            .get::<LoginInfoType>()
            .map(|login_info| LoginInfoExtractor(login_info.clone()))
            .ok_or(StatusCode::UNAUTHORIZED);

        Box::pin(async move { login_info })
    }
}

pub trait AuthHandler<LoginInfoType: Clone + Send + Sync>: Sized + Clone + Send + Sync {
    fn verify_access_token(&self, access_token: &str) -> Result<LoginInfoType, AuthError>;
    fn update_access_token(&self, access_token: String) -> Result<(String, Duration), AuthError>;
}

pub fn is_cookie_expired_by_date(cookie: &Cookie) -> bool {
    if let Some(date_time) = cookie.expires_datetime() {
        let now = std::time::SystemTime::now();
        return date_time < now;
    }

    false
}

pub fn create_auth_cookie<'a>(
    access_token: impl Into<String>,
    expiration_time_delta: Duration,
) -> Cookie<'a> {
    Cookie::build(ACCESS_TOKEN_COOKIE_NAME, access_token.into())
        .http_only(true)
        .secure(true)
        .expires(time::OffsetDateTime::now_utc() + expiration_time_delta)
        .finish()
}

pub fn create_expired_auth_cookie<'a>(access_token: impl Into<String>) -> Cookie<'a> {
    Cookie::build(ACCESS_TOKEN_COOKIE_NAME, access_token.into())
        .http_only(true)
        .secure(true)
        .expires(time::OffsetDateTime::UNIX_EPOCH)
        .finish()
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
            _marker: PhantomData::default(),

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
            _marker: PhantomData::default(),

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

#[pin_project]
pub struct AuthResponseFuture<InnerFutureType, LoginInfoType, AuthHandlerType> {
    _marker: PhantomData<LoginInfoType>,

    #[pin]
    inner_future: InnerFutureType,

    auth_impl: AuthHandlerType,
    access_token: Option<String>,
}

impl<InnerFutureType, ResponseType, ErrorType, LoginInfoType, AuthHandlerType> Future
    for AuthResponseFuture<InnerFutureType, LoginInfoType, AuthHandlerType>
where
    InnerFutureType: Future<Output = Result<ResponseType, ErrorType>>,
    ResponseType: IntoResponse,
    LoginInfoType: Clone + Send + Sync + 'static,
    AuthHandlerType: AuthHandler<LoginInfoType>,
{
    type Output = Result<Response, ErrorType>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        match this.inner_future.poll(cx) {
            Poll::Ready(next_response) => {
                let response = match next_response {
                    Ok(next_response) => {
                        let cookie_jar = CookieJar::new();
                        let cookie_jar = if let Some(access_token) = &this.access_token {
                            if let Ok((access_token, expiration_time_delta)) =
                                this.auth_impl.update_access_token(access_token.clone())
                            {
                                cookie_jar
                                    .add(create_auth_cookie(access_token, expiration_time_delta))
                            } else {
                                cookie_jar
                            }
                        } else {
                            cookie_jar
                        };

                        let mut response = next_response.into_response();
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
                };

                Poll::Ready(response)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<ServiceType, RequestBodyType, ResponseType, LoginInfoType, AuthHandlerType>
    Service<Request<RequestBodyType>>
    for AuthMiddleware<ServiceType, LoginInfoType, AuthHandlerType>
where
    LoginInfoType: Clone + Send + Sync + 'static,
    AuthHandlerType: AuthHandler<LoginInfoType>,
    ServiceType: Service<Request<RequestBodyType>>,
    ServiceType::Future: Future<Output = Result<ResponseType, ServiceType::Error>>,
    ResponseType: IntoResponse,
    RequestBodyType: Body,
{
    type Response = Response;
    type Error = ServiceType::Error;
    type Future = AuthResponseFuture<ServiceType::Future, LoginInfoType, AuthHandlerType>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<RequestBodyType>) -> Self::Future {
        let mut access_token = None;
        let mut login_info = None;
        let cookie_jar = CookieJar::from_headers(req.headers());
        for cookie in cookie_jar.iter() {
            if cookie.name() == ACCESS_TOKEN_COOKIE_NAME && !is_cookie_expired_by_date(&cookie) {
                let at = cookie.value().to_string();
                if let Ok(li) = self.auth_impl.verify_access_token(&at) {
                    login_info = Some(li);
                    access_token = Some(at);
                }
            }
        }

        if let Some(login_info) = login_info {
            req.extensions_mut().insert(login_info);
        }

        AuthResponseFuture {
            _marker: PhantomData::default(),

            inner_future: self.inner.call(req),
            auth_impl: self.auth_impl.clone(),
            access_token,
        }
    }
}
