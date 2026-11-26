//! An in-process HTTP server on an ephemeral loopback port, for a fake AWS
//! peer that speaks the real wire protocol.

use axum::Router;

/// A running fake. The server stops when this is dropped.
pub(crate) struct Loopback {
    endpoint: String,
    server: tokio::task::JoinHandle<()>,
}

impl Loopback {
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }
}

impl Drop for Loopback {
    fn drop(&mut self) {
        self.server.abort();
    }
}

/// Serves `app` until the returned value is dropped.
pub(crate) async fn serve(app: Router) -> Loopback {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind a loopback port");
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.expect("the fake serves");
    });
    Loopback { endpoint, server }
}
