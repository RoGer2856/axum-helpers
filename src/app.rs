use std::net::SocketAddr;

use axum::Router;
use tokio::{sync::watch, task::JoinHandle};

use crate::result_option_inspect::ResultInspector;

pub enum RunServerError {
    TcpBind(std::io::Error),
}

pub trait AxumAppState: Clone {
    fn routes(&self) -> Router;
}

pub struct AxumApp<StateType>
where
    StateType: AxumAppState,
{
    state: StateType,

    should_run_sender: watch::Sender<bool>,
    joinhandles: Vec<JoinHandle<()>>,
}

impl<StateType> AxumApp<StateType>
where
    StateType: AxumAppState,
{
    pub fn new(state: StateType) -> Self {
        let (should_run_sender, _receiver) = watch::channel(true);
        Self {
            state,

            should_run_sender,
            joinhandles: Vec::new(),
        }
    }

    pub fn stop_server(&self) {
        let _ = self.should_run_sender.send(false);
    }

    #[cfg(test)]
    pub fn run_test_server(&self) -> Result<axum_test::TestServer, Box<dyn ::std::error::Error>> {
        use axum_test::TestServer;

        let app = self.state.routes();

        Ok(TestServer::new(app.into_make_service())?)
    }

    pub async fn run_server(&mut self, listener_address: SocketAddr) -> Result<(), RunServerError> {
        let app = self.state.routes();

        let mut should_run_receiver = self.should_run_sender.subscribe();

        log::info!("listening on {}", listener_address);
        let listener = tokio::net::TcpListener::bind(listener_address)
            .await
            .map_err(RunServerError::TcpBind)?;

        let joinhandle = tokio::spawn(async move {
            let _ = axum::serve(listener, app.into_make_service())
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

impl<StateType> Drop for AxumApp<StateType>
where
    StateType: AxumAppState,
{
    fn drop(&mut self) {
        self.stop_server();
    }
}
