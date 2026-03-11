//! Frontend HTTP router with path-based API-key authorization.
//!
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use jsonrpsee::core::BoxError;
use jsonrpsee::server::{
  serve, stop_channel, HttpBody, HttpRequest, HttpResponse, Methods, Server, ServerHandle,
  StopHandle,
};
use tokio::net::TcpListener;
use tower::{Service, ServiceExt};

use crate::authentication::ApiKeyError;
use crate::rpc::register_public_rpc;
use crate::rpc_admin::register_admin_rpc;
use crate::state::SharedState;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum RpcPathKind {
  Public,
  Admin,
}

fn parse_rpc_path(path: &str) -> Option<(String, RpcPathKind)> {
  let parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
  if parts.len() != 2 {
    return None;
  }
  let key = parts[0];
  if key.len() < 32 {
    return None;
  }
  let kind = match parts[1] {
    "json_rpc" => RpcPathKind::Public,
    "admin" => RpcPathKind::Admin,
    _ => return None,
  };
  Some((key.to_string(), kind))
}

fn text_http_response(status: u16, body: &str) -> HttpResponse<HttpBody> {
  HttpResponse::builder()
    .status(status)
    .header("content-type", "text/plain; charset=utf-8")
    .body(HttpBody::from(body.to_string()))
    .expect("response builder with static values should not fail")
}

fn api_key_http_response(err: ApiKeyError) -> HttpResponse<HttpBody> {
  match err {
    ApiKeyError::UnknownKey => text_http_response(401, "Unknown API key"),
    ApiKeyError::NotAdmin => {
      text_http_response(403, "API key is not authorized for admin endpoint")
    }
    ApiKeyError::DisabledKey => text_http_response(403, "API key is disabled"),
    ApiKeyError::ProtectedAdminKey => {
      text_http_response(400, "Admin API key cannot be disabled or deleted")
    }
    ApiKeyError::TokenExhausted => text_http_response(429, "API key has no remaining tokens"),
    ApiKeyError::HourlyLimitExceeded => {
      text_http_response(429, "API key exceeded hourly allowance")
    }
  }
}

#[derive(Clone)]
struct RoutedHttpService {
  state: Arc<SharedState>,
  stop_handle: StopHandle,
  public_methods: Methods,
  admin_methods: Methods,
}

impl Service<HttpRequest<hyper::body::Incoming>> for RoutedHttpService {
  type Response = HttpResponse<HttpBody>;
  type Error = BoxError;
  type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send + 'static>>;

  fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
    Poll::Ready(Ok(()))
  }

  fn call(&mut self, request: HttpRequest<hyper::body::Incoming>) -> Self::Future {
    let state = self.state.clone();
    let stop_handle = self.stop_handle.clone();
    let public_methods = self.public_methods.clone();
    let admin_methods = self.admin_methods.clone();
    Box::pin(async move {
      let path = request.uri().path().to_string();
      let (api_key, path_kind) = match parse_rpc_path(&path) {
        Some(v) => v,
        None => {
          return Ok(text_http_response(
            404,
            "Path must be /{api_key}/json_rpc or /{api_key}/admin",
          ));
        }
      };

      let auth = match path_kind {
        RpcPathKind::Public => state.authorize_public_api_key(&api_key).await,
        RpcPathKind::Admin => state.authorize_admin_api_key(&api_key).await,
      };
      if let Err(err) = auth {
        return Ok(api_key_http_response(err));
      }

      let methods = match path_kind {
        RpcPathKind::Public => public_methods,
        RpcPathKind::Admin => admin_methods,
      };
      Server::builder()
        .to_service_builder()
        .build(methods, stop_handle)
        .oneshot(request)
        .await
        .map_err(|err| -> BoxError { std::io::Error::other(err.to_string()).into() })
    })
  }
}

pub async fn start_rpc_server(
  state: Arc<SharedState>,
  addr: &str,
) -> anyhow::Result<(ServerHandle, SocketAddr)> {
  let listener = TcpListener::bind(addr).await?;
  let local_addr = listener.local_addr()?;

  let public_methods: Methods = register_public_rpc(state.clone())?.into();
  let admin_methods: Methods = register_admin_rpc(state.clone())?.into();
  let (stop_handle, server_handle) = stop_channel();

  tokio::spawn(async move {
    loop {
      let accept_result = tokio::select! {
        res = listener.accept() => res,
        _ = stop_handle.clone().shutdown() => break,
      };
      let (sock, _remote_addr) = match accept_result {
        Ok(v) => v,
        Err(err) => {
          log::warn!("accept failed: {}", err);
          continue;
        }
      };

      let stop_handle2 = stop_handle.clone();
      let svc = RoutedHttpService {
        state: state.clone(),
        stop_handle: stop_handle2.clone(),
        public_methods: public_methods.clone(),
        admin_methods: admin_methods.clone(),
      };

      tokio::spawn(async move {
        let _ = stop_handle2;
        if let Err(err) = serve(sock, svc).await {
          log::warn!("connection error: {}", err);
        }
      });
    }
  });

  Ok((server_handle, local_addr))
}

pub async fn start_rpc(state: Arc<SharedState>) -> anyhow::Result<()> {
  let (handle, addr) = start_rpc_server(state, "127.0.0.1:8545").await?;
  log::info!("Server listening on {}", addr);
  log::info!("Public endpoint: http://{}/{{api_key}}/json_rpc", addr);
  log::info!("Admin endpoint: http://{}/{{admin_api_key}}/admin", addr);
  handle.stopped().await;
  Ok(())
}
