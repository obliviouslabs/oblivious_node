//! dstack/Phala attestation helpers exposed by the HTTP frontend.
//!
//! The application runs inside a Phala dstack CVM by mounting
//! `/var/run/dstack.sock`.  These helpers proxy the small subset of the dstack
//! guest-agent API that external verifiers need: `/GetQuote` and `/Info`.

use std::fmt;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

use serde::Serialize;
use sha2::{Digest, Sha256, Sha512};

const DEFAULT_DSTACK_SOCKET_PATH: &str = "/var/run/dstack.sock";
const DEFAULT_ATTESTED_TLS_CERT_DIR: &str = "/etc/letsencrypt/live";
const MAX_REPORT_DATA_HEX_CHARS: usize = 64 * 2;
const CHALLENGE_HEX_CHARS: usize = 32 * 2;

#[derive(Serialize)]
struct AttestedTlsCertResponse {
  domain: String,
  certificate: String,
  certificate_sha256: String,
  challenge: String,
  report_data: String,
  attestation: serde_json::Value,
}

#[derive(Debug)]
/// Error returned while proxying verifier requests to dstack.
pub enum AttestationError {
  /// The public verifier request was malformed.
  BadRequest(String),
  /// The dstack guest-agent socket could not be reached.
  SocketUnavailable(String),
  /// The dstack guest-agent returned a bad or unsuccessful HTTP response.
  DstackHttp(String),
  /// The local async/blocking bridge failed.
  Internal(String),
}

impl fmt::Display for AttestationError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      AttestationError::BadRequest(msg)
      | AttestationError::SocketUnavailable(msg)
      | AttestationError::DstackHttp(msg)
      | AttestationError::Internal(msg) => f.write_str(msg),
    }
  }
}

/// Return the configured dstack guest-agent socket path.
pub fn dstack_socket_path() -> String {
  std::env::var("DSTACK_SOCKET_PATH").unwrap_or_else(|_| DEFAULT_DSTACK_SOCKET_PATH.to_string())
}

/// Fetch a dstack TDX quote for the optional public `report_data` query string.
pub async fn quote_for_query(query: Option<&str>) -> Result<String, AttestationError> {
  let report_data = report_data_from_query(query)?;
  let socket_path = dstack_socket_path();
  tokio::task::spawn_blocking(move || quote_from_socket(&socket_path, &report_data))
    .await
    .map_err(|err| AttestationError::Internal(format!("attestation task failed: {}", err)))?
}

/// Fetch dstack `/Info` JSON for external application verifiers.
pub async fn info() -> Result<String, AttestationError> {
  let socket_path = dstack_socket_path();
  tokio::task::spawn_blocking(move || info_from_socket(&socket_path))
    .await
    .map_err(|err| AttestationError::Internal(format!("attestation task failed: {}", err)))?
}

/// Fetch the configured TLS certificate and a TDX quote binding it to a fresh challenge.
pub async fn attested_tls_cert_for_query(query: Option<&str>) -> Result<String, AttestationError> {
  let (domain, challenge) = attested_tls_params_from_query(query)?;
  let socket_path = dstack_socket_path();
  tokio::task::spawn_blocking(move || {
    attested_tls_cert_from_socket(&socket_path, domain, challenge)
  })
  .await
  .map_err(|err| AttestationError::Internal(format!("attestation task failed: {}", err)))?
}

fn quote_from_socket(socket_path: &str, report_data: &str) -> Result<String, AttestationError> {
  let request = format!(
    "GET /GetQuote?report_data={} HTTP/1.1\r\nHost: dstack\r\nConnection: close\r\n\r\n",
    report_data
  );
  request_unix_http(socket_path, request.as_bytes())
}

fn info_from_socket(socket_path: &str) -> Result<String, AttestationError> {
  let request = b"GET /Info HTTP/1.1\r\nHost: dstack\r\nConnection: close\r\n\r\n";
  request_unix_http(socket_path, request)
}

fn attested_tls_cert_from_socket(
  socket_path: &str,
  domain: String,
  challenge: String,
) -> Result<String, AttestationError> {
  let certificate = fs::read_to_string(tls_cert_path(&domain)).map_err(|err| {
    AttestationError::Internal(format!("failed to read attested TLS certificate: {}", err))
  })?;
  let certificate_sha256 = Sha256::digest(certificate.as_bytes());
  let certificate_sha256_hex = hex::encode(certificate_sha256);
  let report_data = report_data_for_attested_tls_cert(&domain, &certificate_sha256_hex, &challenge);
  let attestation = quote_from_socket(socket_path, &format!("0x{}", report_data))?;
  let attestation: serde_json::Value = serde_json::from_str(&attestation).map_err(|err| {
    AttestationError::DstackHttp(format!("dstack returned non-JSON quote: {}", err))
  })?;

  serde_json::to_string(&AttestedTlsCertResponse {
    domain,
    certificate,
    certificate_sha256: format!("0x{}", certificate_sha256_hex),
    challenge: format!("0x{}", challenge),
    report_data: format!("0x{}", report_data),
    attestation,
  })
  .map_err(|err| AttestationError::Internal(format!("failed to serialize response: {}", err)))
}

fn request_unix_http(socket_path: &str, request: &[u8]) -> Result<String, AttestationError> {
  let mut stream = UnixStream::connect(socket_path).map_err(|err| {
    AttestationError::SocketUnavailable(format!(
      "dstack socket unavailable at {}: {}",
      socket_path, err
    ))
  })?;
  stream.write_all(request).map_err(|err| {
    AttestationError::SocketUnavailable(format!("failed to write dstack request: {}", err))
  })?;
  stream.shutdown(std::net::Shutdown::Write).ok();

  let mut response = Vec::new();
  stream.read_to_end(&mut response).map_err(|err| {
    AttestationError::SocketUnavailable(format!("failed to read dstack response: {}", err))
  })?;

  parse_http_response(&response)
}

fn parse_http_response(response: &[u8]) -> Result<String, AttestationError> {
  let split = response
    .windows(4)
    .position(|window| window == b"\r\n\r\n")
    .ok_or_else(|| AttestationError::DstackHttp("malformed dstack HTTP response".to_string()))?;
  let (headers, body_with_sep) = response.split_at(split);
  let body = &body_with_sep[4..];
  let headers_text = std::str::from_utf8(headers).map_err(|_| {
    AttestationError::DstackHttp("dstack response headers were not UTF-8".to_string())
  })?;
  let mut header_lines = headers_text.lines();
  let status_line = header_lines
    .next()
    .ok_or_else(|| AttestationError::DstackHttp("missing dstack status line".to_string()))?;
  let status = status_line
    .split_whitespace()
    .nth(1)
    .and_then(|code| code.parse::<u16>().ok())
    .ok_or_else(|| AttestationError::DstackHttp("bad dstack status line".to_string()))?;

  let is_chunked = headers_text
    .lines()
    .any(|line| line.to_ascii_lowercase().trim() == "transfer-encoding: chunked");
  let body = if is_chunked { decode_chunked_body(body)? } else { body.to_vec() };
  let body_text = String::from_utf8(body)
    .map_err(|_| AttestationError::DstackHttp("dstack response body was not UTF-8".to_string()))?;

  if !(200..300).contains(&status) {
    return Err(AttestationError::DstackHttp(format!(
      "dstack returned HTTP {}: {}",
      status, body_text
    )));
  }

  Ok(body_text)
}

fn decode_chunked_body(mut body: &[u8]) -> Result<Vec<u8>, AttestationError> {
  let mut decoded = Vec::new();
  loop {
    let line_end = body
      .windows(2)
      .position(|window| window == b"\r\n")
      .ok_or_else(|| AttestationError::DstackHttp("malformed chunked body".to_string()))?;
    let size_line = std::str::from_utf8(&body[..line_end])
      .map_err(|_| AttestationError::DstackHttp("chunk size was not UTF-8".to_string()))?;
    let size_hex = size_line.split(';').next().unwrap_or("").trim();
    let size = usize::from_str_radix(size_hex, 16)
      .map_err(|_| AttestationError::DstackHttp("bad chunk size".to_string()))?;
    body = &body[line_end + 2..];
    if size == 0 {
      break;
    }
    if body.len() < size + 2 || &body[size..size + 2] != b"\r\n" {
      return Err(AttestationError::DstackHttp("truncated chunked body".to_string()));
    }
    decoded.extend_from_slice(&body[..size]);
    body = &body[size + 2..];
  }
  Ok(decoded)
}

fn report_data_from_query(query: Option<&str>) -> Result<String, AttestationError> {
  let Some(query) = query else {
    return Ok("0x".to_string());
  };

  let mut report_data = "";
  for pair in query.split('&') {
    let mut kv = pair.splitn(2, '=');
    let key = kv.next().unwrap_or("");
    let value = kv.next().unwrap_or("");
    if key == "report_data" || key == "reportData" {
      report_data = value;
      break;
    }
  }

  normalize_report_data_hex(report_data)
}

fn attested_tls_params_from_query(
  query: Option<&str>,
) -> Result<(String, String), AttestationError> {
  let Some(query) = query else {
    return Err(AttestationError::BadRequest(
      "missing domain and challenge query parameters".to_string(),
    ));
  };

  let mut domain = "";
  let mut challenge = "";
  for pair in query.split('&') {
    let mut kv = pair.splitn(2, '=');
    let key = kv.next().unwrap_or("");
    let value = kv.next().unwrap_or("");
    match key {
      "domain" => domain = value,
      "challenge" => challenge = value,
      _ => {}
    }
  }

  Ok((normalize_domain(domain)?, normalize_challenge_hex(challenge)?))
}

fn normalize_report_data_hex(value: &str) -> Result<String, AttestationError> {
  let value = value.strip_prefix("0x").unwrap_or(value);
  if value.len() > MAX_REPORT_DATA_HEX_CHARS {
    return Err(AttestationError::BadRequest("report_data must be at most 64 bytes".to_string()));
  }
  if !value.len().is_multiple_of(2) {
    return Err(AttestationError::BadRequest(
      "report_data hex must contain an even number of characters".to_string(),
    ));
  }
  if !value.chars().all(|ch| ch.is_ascii_hexdigit()) {
    return Err(AttestationError::BadRequest(
      "report_data must be hex, optionally prefixed with 0x".to_string(),
    ));
  }
  Ok(format!("0x{}", value.to_ascii_lowercase()))
}

fn normalize_challenge_hex(value: &str) -> Result<String, AttestationError> {
  let value = value.strip_prefix("0x").unwrap_or(value);
  if value.len() != CHALLENGE_HEX_CHARS {
    return Err(AttestationError::BadRequest("challenge must be exactly 32 bytes".to_string()));
  }
  if !value.chars().all(|ch| ch.is_ascii_hexdigit()) {
    return Err(AttestationError::BadRequest(
      "challenge must be hex, optionally prefixed with 0x".to_string(),
    ));
  }
  Ok(value.to_ascii_lowercase())
}

fn normalize_domain(value: &str) -> Result<String, AttestationError> {
  let domain = value.trim().trim_end_matches('.').to_ascii_lowercase();
  if domain.is_empty() || domain.len() > 253 {
    return Err(AttestationError::BadRequest("domain is missing or too long".to_string()));
  }
  if !domain.chars().all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '.') {
    return Err(AttestationError::BadRequest("domain contains unsupported characters".to_string()));
  }
  for label in domain.split('.') {
    if label.is_empty() || label.starts_with('-') || label.ends_with('-') || label.len() > 63 {
      return Err(AttestationError::BadRequest("domain is malformed".to_string()));
    }
  }
  Ok(domain)
}

fn tls_cert_path(domain: &str) -> PathBuf {
  if let Ok(path) = std::env::var("ATTESTED_TLS_CERT_PATH") {
    return PathBuf::from(path);
  }
  let base_dir = std::env::var("ATTESTED_TLS_CERT_DIR")
    .unwrap_or_else(|_| DEFAULT_ATTESTED_TLS_CERT_DIR.to_string());
  PathBuf::from(base_dir).join(domain).join("fullchain.pem")
}

fn report_data_for_attested_tls_cert(
  domain: &str,
  certificate_sha256_hex: &str,
  challenge_hex: &str,
) -> String {
  let payload = format!(
    "domain={}\ncertificate_sha256=0x{}\nchallenge=0x{}\n",
    domain, certificate_sha256_hex, challenge_hex
  );
  hex::encode(Sha512::digest(payload.as_bytes()))
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::io::{Read, Write};
  use std::os::unix::net::UnixListener;
  use std::thread;
  use std::time::{SystemTime, UNIX_EPOCH};

  #[test]
  fn report_data_query_accepts_empty_and_hex_aliases() {
    assert_eq!(report_data_from_query(None).unwrap(), "0x");
    assert_eq!(report_data_from_query(Some("reportData=0xAABB&x=1")).unwrap(), "0xaabb");
    assert_eq!(report_data_from_query(Some("x=1&report_data=0011")).unwrap(), "0x0011");
  }

  #[test]
  fn report_data_query_rejects_bad_hex() {
    assert!(matches!(
      report_data_from_query(Some("report_data=abc")),
      Err(AttestationError::BadRequest(_))
    ));
    assert!(matches!(
      report_data_from_query(Some("report_data=zz")),
      Err(AttestationError::BadRequest(_))
    ));
    let too_long = format!("report_data={}", "00".repeat(65));
    assert!(matches!(
      report_data_from_query(Some(&too_long)),
      Err(AttestationError::BadRequest(_))
    ));
  }

  #[test]
  fn parses_chunked_http_response() {
    let response =
      b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
    assert_eq!(parse_http_response(response).unwrap(), "hello world");
  }

  #[test]
  fn quote_from_socket_posts_report_data() {
    let socket_path = std::env::temp_dir().join(format!(
      "oblivious-node-dstack-{}.sock",
      SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
    ));
    let listener = UnixListener::bind(&socket_path).unwrap();
    let socket_path_for_client = socket_path.clone();

    let handle = thread::spawn(move || {
      let (mut stream, _) = listener.accept().unwrap();
      let mut request = String::new();
      stream.read_to_string(&mut request).unwrap();
      assert!(request.starts_with("GET /GetQuote?report_data=0x1234 HTTP/1.1"));
      let body = r#"{"quote":"0xabc","event_log":"[]"}"#;
      write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
      )
      .unwrap();
    });

    let body = quote_from_socket(socket_path_for_client.to_str().unwrap(), "0x1234").unwrap();
    assert_eq!(body, r#"{"quote":"0xabc","event_log":"[]"}"#);
    handle.join().unwrap();
    let _ = std::fs::remove_file(socket_path);
  }
}
