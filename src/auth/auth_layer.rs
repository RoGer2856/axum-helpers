use std::{
    future::Future,
    marker::PhantomData,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use axum::{
    extract::Request,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use axum_extra::extract::{
    cookie::{Cookie, SameSite},
    CookieJar,
};
use http_body::Body;
use time::OffsetDateTime;
use tower::{Layer, Service};

use super::{
    auth_handler::{AccessToken, RefreshToken},
    AuthHandler, AuthLogoutResponse,
};

const ACCESS_TOKEN_COOKIE_NAME: &str = "access_token";
const REFRESH_TOKEN_COOKIE_NAME: &str = "refresh_token";

pub(super) struct AccessTokenVerificationResultExtension<LoginInfoType: Send + Sync + 'static>(
    pub(super) Result<Arc<LoginInfoType>, StatusCode>,
);

impl<LoginInfoType: Send + Sync + 'static> Clone
    for AccessTokenVerificationResultExtension<LoginInfoType>
{
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

#[derive(Clone)]
pub(super) struct RefreshTokenVerificationResultExtension(
    pub(super) (RefreshToken, Result<(), StatusCode>),
);

#[derive(Clone)]
pub(super) struct AuthLogoutExtension(pub(super) AuthLogoutResponse);

pub fn is_cookie_expired_by_date(cookie: &Cookie) -> bool {
    if let Some(date_time) = cookie.expires_datetime() {
        let now = std::time::SystemTime::now();
        return date_time < now;
    }

    false
}

pub(super) fn create_access_token_cookie<'a>(
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

pub(super) fn create_refresh_token_cookie<'a>(
    refresh_token: impl Into<String>,
    expires_at: OffsetDateTime,
    path: impl Into<String>,
) -> Cookie<'a> {
    Cookie::build((REFRESH_TOKEN_COOKIE_NAME, refresh_token.into()))
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Strict)
        .expires(expires_at)
        .path(path.into())
        .build()
}

#[derive(Clone)]
pub struct AuthLayer<
    LoginInfoType: Send + Sync + 'static,
    AuthHandlerType: AuthHandler<LoginInfoType>,
> {
    _marker: PhantomData<LoginInfoType>,

    auth_impl: AuthHandlerType,
}

impl<LoginInfoType: Send + Sync + 'static, AuthHandlerType: AuthHandler<LoginInfoType>>
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
        LoginInfoType: Send + Sync + 'static,
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
    LoginInfoType: Send + Sync + 'static,
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
    LoginInfoType: Send + Sync + 'static,
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
            let mut received_access_token_login_result_pair = None;
            let mut received_refresh_token = None;
            let cookie_jar = CookieJar::from_headers(req.headers());
            for cookie in cookie_jar.iter() {
                if cookie.name() == ACCESS_TOKEN_COOKIE_NAME && !is_cookie_expired_by_date(cookie) {
                    let replace = match &received_access_token_login_result_pair {
                        Some((_access_token, Ok(_login_info))) => false,
                        Some((_access_token, Err(_))) => true,
                        None => true,
                    };

                    if replace {
                        let access_token = AccessToken(cookie.value().to_string());
                        let verification_result = auth_impl
                            .verify_access_token(&access_token)
                            .await
                            .map(|login_info| Arc::new(login_info));
                        received_access_token_login_result_pair =
                            Some((access_token, verification_result))
                    }
                } else if cookie.name() == REFRESH_TOKEN_COOKIE_NAME
                    && !is_cookie_expired_by_date(cookie)
                {
                    let replace = match &received_refresh_token {
                        Some((_refresh_token, Ok(()))) => false,
                        Some((_refresh_token, Err(_))) => true,
                        None => true,
                    };

                    if replace {
                        let refresh_token = RefreshToken(cookie.value().to_string());
                        let verification_result =
                            auth_impl.verify_refresh_token(&refresh_token).await;
                        received_refresh_token = Some((refresh_token, verification_result));
                    }
                }
            }

            if let Some((_at, login_result)) = &received_access_token_login_result_pair {
                req.extensions_mut()
                    .insert(AccessTokenVerificationResultExtension(login_result.clone()));
            }

            if let Some(refresh_token) = &received_refresh_token {
                req.extensions_mut()
                    .insert(RefreshTokenVerificationResultExtension(
                        refresh_token.clone(),
                    ));
            }

            let next_response = inner.call(req).await;

            match next_response {
                Ok(next_response) => {
                    let mut response = next_response.into_response();

                    let cookie_jar = CookieJar::new();

                    let cookie_jar = if let Some(auth_logout_extension) =
                        response.extensions_mut().remove::<AuthLogoutExtension>()
                    {
                        if let Some((access_token, Ok(login_info))) =
                            &received_access_token_login_result_pair
                        {
                            auth_impl
                                .revoke_access_token(access_token, login_info)
                                .await;
                        }

                        if let Some((refresh_token, Ok(()))) = &received_refresh_token {
                            auth_impl.revoke_refresh_token(refresh_token).await;
                        }

                        let cookie_jar = cookie_jar
                            .add(create_access_token_cookie(
                                "",
                                time::OffsetDateTime::UNIX_EPOCH,
                                auth_logout_extension
                                    .0
                                    .access_token_path
                                    .as_deref()
                                    .unwrap_or("/"),
                            ))
                            .add(create_access_token_cookie(
                                "",
                                time::OffsetDateTime::UNIX_EPOCH,
                                auth_logout_extension
                                    .0
                                    .refresh_token_path
                                    .as_deref()
                                    .unwrap_or("/"),
                            ));

                        cookie_jar
                    } else if let Some((access_token, Ok(login_info))) =
                        &received_access_token_login_result_pair
                    {
                        if let Some((access_token, expiration_time_delta)) = auth_impl
                            .update_access_token(access_token, login_info)
                            .await
                        {
                            cookie_jar.add(create_access_token_cookie(
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
