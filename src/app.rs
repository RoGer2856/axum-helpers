use std::net::SocketAddr;

use axum::Router;
use tokio::{sync::watch, task::JoinHandle};

use crate::result_option_inspect::ResultInspector;

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

    pub fn run_server(&mut self, listener_address: SocketAddr) {
        let app = self.state.routes();

        let mut should_run_receiver = self.should_run_sender.subscribe();

        log::info!("listening on {}", listener_address);

        let joinhandle = tokio::spawn(async move {
            let _ = axum::Server::bind(&listener_address)
                .serve(app.into_make_service())
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
