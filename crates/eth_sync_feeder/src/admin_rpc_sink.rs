//! HTTP JSON-RPC sink for pushing updates into `eth_privatestate` admin RPC.
//!
use std::error::Error as StdError;
use std::fmt::{Display, Formatter};
use std::time::Duration;

use eth_privatestate::state::MissingProofQuery;
use reqwest::{Client, StatusCode, Url};
use serde_json::{json, Value};

use crate::{AdminSink, BlockDelta, FeederFuture};

const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_RETRY_ATTEMPTS: u32 = 3;
const DEFAULT_RETRY_BACKOFF: Duration = Duration::from_millis(250);

/// HTTP admin sink implementation.
#[derive(Clone, Debug)]
pub struct HttpAdminSink {
  client: Client,
  admin_endpoint_url: String,
  retry_attempts: u32,
  retry_backoff: Duration,
}

impl HttpAdminSink {
  /// Builds sink from a full admin endpoint URL, for example
  /// `http://127.0.0.1:8545/<admin_key>/admin`.
  pub fn new(admin_endpoint_url: impl Into<String>) -> Result<Self, SinkError> {
    let admin_endpoint_url = admin_endpoint_url.into();
    validate_admin_endpoint_url(&admin_endpoint_url)?;

    let client =
      Client::builder().timeout(DEFAULT_REQUEST_TIMEOUT).build().map_err(SinkError::BuildClient)?;

    Ok(Self {
      client,
      admin_endpoint_url,
      retry_attempts: DEFAULT_RETRY_ATTEMPTS,
      retry_backoff: DEFAULT_RETRY_BACKOFF,
    })
  }

  /// Convenience constructor from base server URL and admin API key.
  pub fn from_base_url(admin_base_url: &str, admin_api_key: &str) -> Result<Self, SinkError> {
    if admin_api_key.len() < 32 {
      return Err(SinkError::InvalidConfig(
        "admin API key must be at least 32 bytes/chars".to_string(),
      ));
    }

    let admin_base_url = admin_base_url.trim_end_matches('/');
    let admin_endpoint_url = format!("{}/{}/admin", admin_base_url, admin_api_key);
    Self::new(admin_endpoint_url)
  }

  async fn call_bool_method(&self, method: &'static str, params: Value) -> Result<(), SinkError> {
    let result = self.call_method_result(method, params).await?;
    if result.as_bool().unwrap_or(false) {
      return Ok(());
    }
    Err(SinkError::UnexpectedResponse(format!(
      "method {} returned non-bool-true result: {}",
      method, result
    )))
  }

  async fn call_method_result(
    &self,
    method: &'static str,
    params: Value,
  ) -> Result<Value, SinkError> {
    for attempt in 0..self.retry_attempts {
      let res = self.call_method_result_once(method, params.clone()).await;
      match res {
        Ok(v) => return Ok(v),
        Err(err) => {
          let last_attempt = attempt + 1 >= self.retry_attempts;
          if last_attempt || !err.is_retryable() {
            return Err(err);
          }
          tokio::time::sleep(self.retry_backoff).await;
        }
      }
    }
    Err(SinkError::UnexpectedResponse("retry loop terminated unexpectedly".to_string()))
  }

  async fn call_method_result_once(
    &self,
    method: &'static str,
    params: Value,
  ) -> Result<Value, SinkError> {
    let payload = json!({
      "jsonrpc": "2.0",
      "method": method,
      "params": params,
      "id": 1
    });

    let response = self
      .client
      .post(&self.admin_endpoint_url)
      .json(&payload)
      .send()
      .await
      .map_err(SinkError::Transport)?;
    let status = response.status();
    let body = response.text().await.map_err(SinkError::Transport)?;

    if !status.is_success() {
      return Err(SinkError::HttpStatus { code: status, body });
    }

    let json_body: Value = serde_json::from_str(&body).map_err(SinkError::DecodeResponse)?;
    if let Some(err) = json_body.get("error") {
      let code = err.get("code").and_then(Value::as_i64).unwrap_or_default();
      let message = err.get("message").and_then(Value::as_str).unwrap_or("").to_string();
      return Err(SinkError::Rpc { code, message });
    }

    json_body
      .get("result")
      .cloned()
      .ok_or_else(|| SinkError::UnexpectedResponse(format!("missing result field: {}", body)))
  }
}

impl AdminSink for HttpAdminSink {
  type Error = SinkError;

  fn submit_node_rlp_hex(&mut self, node_hex: String) -> FeederFuture<'_, Result<(), Self::Error>> {
    Box::pin(async move { self.call_bool_method("admin_put_node", json!(node_hex)).await })
  }

  fn set_root_by_hash(
    &mut self,
    block_hash_hex: String,
    state_root_hex: String,
  ) -> FeederFuture<'_, Result<(), Self::Error>> {
    Box::pin(async move {
      self.call_bool_method("admin_set_root_by_hash", json!([block_hash_hex, state_root_hex])).await
    })
  }

  fn set_root_by_number(
    &mut self,
    block_number: u64,
    state_root_hex: String,
  ) -> FeederFuture<'_, Result<(), Self::Error>> {
    Box::pin(async move {
      self.call_bool_method("admin_set_root", json!([block_number, state_root_hex])).await
    })
  }

  fn publish_block_delta<'a>(
    &'a mut self,
    block: &'a BlockDelta,
    publish_root_by_number: bool,
  ) -> FeederFuture<'a, Result<(), Self::Error>> {
    let block_number = block.number;
    let block_hash_hex = block.hash_hex.clone();
    let state_root_hex = block.state_root_hex.clone();
    let node_hexes: Vec<String> =
      block.changed_trie_nodes_rlp.iter().map(|node| format!("0x{}", hex::encode(node))).collect();

    Box::pin(async move {
      self
        .call_bool_method(
          "admin_apply_block_delta",
          json!([block_number, block_hash_hex, state_root_hex, node_hexes, publish_root_by_number]),
        )
        .await
    })
  }

  fn take_missing_proof_queries(
    &mut self,
  ) -> FeederFuture<'_, Result<Vec<MissingProofQuery>, Self::Error>> {
    Box::pin(async move {
      let result = self.call_method_result("admin_take_missing_nodes", json!([])).await?;
      serde_json::from_value::<Vec<MissingProofQuery>>(result).map_err(SinkError::DecodeResponse)
    })
  }
}

/// Admin sink error.
#[derive(Debug)]
pub enum SinkError {
  /// Invalid sink configuration.
  InvalidConfig(String),
  /// Failed to construct HTTP client.
  BuildClient(reqwest::Error),
  /// Network/transport error.
  Transport(reqwest::Error),
  /// Non-2xx HTTP response.
  HttpStatus {
    /// HTTP status code.
    code: StatusCode,
    /// Raw response body.
    body: String,
  },
  /// Failed to decode JSON-RPC response.
  DecodeResponse(serde_json::Error),
  /// JSON-RPC error object returned by server.
  Rpc {
    /// JSON-RPC code.
    code: i64,
    /// JSON-RPC message.
    message: String,
  },
  /// Response body does not match expected schema.
  UnexpectedResponse(String),
}

impl SinkError {
  fn is_retryable(&self) -> bool {
    match self {
      Self::Transport(_) => true,
      Self::HttpStatus { code, .. } => {
        code.is_server_error() || *code == StatusCode::TOO_MANY_REQUESTS
      }
      Self::InvalidConfig(_)
      | Self::BuildClient(_)
      | Self::DecodeResponse(_)
      | Self::Rpc { .. }
      | Self::UnexpectedResponse(_) => false,
    }
  }
}

impl Display for SinkError {
  fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
    match self {
      Self::InvalidConfig(msg) => write!(f, "invalid config: {}", msg),
      Self::BuildClient(err) => write!(f, "failed to build HTTP client: {}", err),
      Self::Transport(err) => write!(f, "transport error: {}", err),
      Self::HttpStatus { code, body } => write!(f, "http status {}: {}", code, body),
      Self::DecodeResponse(err) => write!(f, "failed to decode json-rpc response: {}", err),
      Self::Rpc { code, message } => write!(f, "json-rpc error {}: {}", code, message),
      Self::UnexpectedResponse(body) => write!(f, "unexpected json-rpc response: {}", body),
    }
  }
}

impl StdError for SinkError {
  fn source(&self) -> Option<&(dyn StdError + 'static)> {
    match self {
      Self::BuildClient(err) => Some(err),
      Self::Transport(err) => Some(err),
      Self::DecodeResponse(err) => Some(err),
      Self::InvalidConfig(_)
      | Self::HttpStatus { .. }
      | Self::Rpc { .. }
      | Self::UnexpectedResponse(_) => None,
    }
  }
}

fn validate_admin_endpoint_url(url: &str) -> Result<(), SinkError> {
  let parsed = Url::parse(url)
    .map_err(|err| SinkError::InvalidConfig(format!("invalid admin endpoint url: {}", err)))?;
  if parsed.scheme() != "http" && parsed.scheme() != "https" {
    return Err(SinkError::InvalidConfig("admin endpoint URL must use http or https".to_string()));
  }
  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn sink_from_base_url_builds_expected_endpoint() {
    let sink = HttpAdminSink::from_base_url(
      "http://127.0.0.1:8545/",
      "olabs-admin-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    )
    .unwrap();
    assert_eq!(
      sink.admin_endpoint_url,
      "http://127.0.0.1:8545/olabs-admin-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/admin"
    );
    assert_eq!(sink.retry_attempts, DEFAULT_RETRY_ATTEMPTS);
    assert_eq!(sink.retry_backoff, DEFAULT_RETRY_BACKOFF);
  }

  #[test]
  fn sink_rejects_invalid_config() {
    let err = HttpAdminSink::from_base_url("http://127.0.0.1:8545", "short").unwrap_err();
    assert!(matches!(err, SinkError::InvalidConfig(_)));

    let err = HttpAdminSink::new("ftp://127.0.0.1:8545/a/admin").unwrap_err();
    assert!(matches!(err, SinkError::InvalidConfig(_)));
  }

  #[test]
  fn retry_policy_matches_error_classification() {
    let retryable =
      SinkError::HttpStatus { code: StatusCode::INTERNAL_SERVER_ERROR, body: "oops".to_string() };
    assert!(retryable.is_retryable());

    let too_many = SinkError::HttpStatus {
      code: StatusCode::TOO_MANY_REQUESTS,
      body: "ratelimited".to_string(),
    };
    assert!(too_many.is_retryable());

    let non_retryable = SinkError::Rpc { code: -32602, message: "invalid".to_string() };
    assert!(!non_retryable.is_retryable());
  }
}
