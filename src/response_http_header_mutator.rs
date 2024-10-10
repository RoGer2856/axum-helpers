use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use axum::{
    extract::Request,
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use http_body::Body;
use tower::{Layer, Service};

#[derive(Clone)]
pub struct ResponseHttpHeaderMutatorLayer<
    CallbackErrorType: IntoResponse + Send + Sync + 'static,
    CallbackType: Fn(&HeaderMap, &mut HeaderMap) -> Result<(), CallbackErrorType> + Send + Sync + 'static,
> {
    callback: Arc<CallbackType>,
}

impl<
        CallbackErrorType: IntoResponse + Send + Sync + 'static,
        CallbackType: Fn(&HeaderMap, &mut HeaderMap) -> Result<(), CallbackErrorType> + Send + Sync + 'static,
    > ResponseHttpHeaderMutatorLayer<CallbackErrorType, CallbackType>
{
    pub fn new(callback: CallbackType) -> Self {
        Self {
            callback: Arc::new(callback),
        }
    }
}

impl<
        InnerServiceType,
        CallbackErrorType: IntoResponse + Send + Sync + 'static,
        CallbackType: Fn(&HeaderMap, &mut HeaderMap) -> Result<(), CallbackErrorType> + Send + Sync + 'static,
    > Layer<InnerServiceType> for ResponseHttpHeaderMutatorLayer<CallbackErrorType, CallbackType>
{
    type Service =
        ResponseHttpHeaderMutatorMiddleware<InnerServiceType, CallbackErrorType, CallbackType>;

    fn layer(&self, inner: InnerServiceType) -> Self::Service {
        ResponseHttpHeaderMutatorMiddleware {
            inner,
            callback: self.callback.clone(),
        }
    }
}

#[derive(Clone)]
pub struct ResponseHttpHeaderMutatorMiddleware<
    InnerServiceType,
    CallbackErrorType: IntoResponse + Send + Sync + 'static,
    CallbackType: Fn(&HeaderMap, &mut HeaderMap) -> Result<(), CallbackErrorType> + Send + Sync + 'static,
> {
    inner: InnerServiceType,
    callback: Arc<CallbackType>,
}

impl<InnerServiceType, RequestBodyType, InnerResponseType, CallbackErrorType, CallbackType>
    Service<Request<RequestBodyType>>
    for ResponseHttpHeaderMutatorMiddleware<InnerServiceType, CallbackErrorType, CallbackType>
where
    CallbackErrorType: IntoResponse + Send + Sync + 'static,
    CallbackType:
        Fn(&HeaderMap, &mut HeaderMap) -> Result<(), CallbackErrorType> + Send + Sync + 'static,
    InnerServiceType: Service<Request<RequestBodyType>> + Clone + Send + 'static,
    InnerServiceType::Future:
        Future<Output = Result<InnerResponseType, InnerServiceType::Error>> + Send,
    InnerServiceType::Error: Send,
    InnerResponseType: IntoResponse + Send,
    RequestBodyType: Body + Send + 'static,
{
    type Response = Result<Response, CallbackErrorType>;
    type Error = InnerServiceType::Error;
    type Future =
        Pin<Box<dyn Future<Output = Result<Self::Response, InnerServiceType::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<RequestBodyType>) -> Self::Future {
        let request_headers = req.headers().clone();
        let mut inner = self.inner.clone();
        let callback = self.callback.clone();
        Box::pin(async move {
            let next_response = inner.call(req).await;

            match next_response {
                Ok(next_response) => {
                    let mut response = next_response.into_response();

                    if let Err(e) = callback.as_ref()(&request_headers, response.headers_mut()) {
                        Ok(Err(e))
                    } else {
                        Ok(Ok(response))
                    }
                }
                Err(e) => Err(e),
            }
        })
    }
}
