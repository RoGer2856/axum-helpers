use std::net::SocketAddr;

use axum::Router;
use tokio::{sync::watch, task::JoinHandle};

#[derive(Debug)]
pub enum RunServerError {
    TcpBind(std::io::Error),
}

pub struct AxumApp {
    router: Router,

    should_run_sender: watch::Sender<bool>,
    joinhandles: Vec<JoinHandle<()>>,
}

impl AxumApp {
    pub fn new(router: Router) -> Self {
        let (should_run_sender, _receiver) = watch::channel(true);
        Self {
            router,

            should_run_sender,
            joinhandles: Vec::new(),
        }
    }

    pub fn stop_server(&self) {
        let _ = self.should_run_sender.send(false);
    }

    #[cfg(test)]
    pub fn spawn_test_server(&self) -> Result<axum_test::TestServer, Box<dyn ::std::error::Error>> {
        use axum_test::TestServer;

        let router = self.router.clone();

        Ok(TestServer::new(router.into_make_service())?)
    }

    pub async fn spawn_server(
        &mut self,
        listener_address: SocketAddr,
    ) -> Result<(), RunServerError> {
        let router = self.router.clone();

        let mut should_run_receiver = self.should_run_sender.subscribe();

        log::info!("listening on {}", listener_address);
        let listener = tokio::net::TcpListener::bind(listener_address)
            .await
            .map_err(RunServerError::TcpBind)?;

        let joinhandle = tokio::spawn(async move {
            let _ = axum::serve(listener, router.into_make_service())
                .with_graceful_shutdown(async move {
                    while should_run_receiver.changed().await.is_ok() {
                        if !*should_run_receiver.borrow() {
                            break;
                        }
                    }
                })
                .await
                .inspect_err(|e| log::warn!("Server error = {e}"));
        });

        self.joinhandles.push(joinhandle);

        Ok(())
    }

    pub async fn join(&mut self) {
        for joinhandle in self.joinhandles.drain(..) {
            let _ = joinhandle
                .await
                .inspect_err(|e| log::warn!("Could not join server task, error = {e}"));
        }
    }
}

impl Drop for AxumApp {
    fn drop(&mut self) {
        self.stop_server();
    }
}
