//! API-key authentication and rate-limit state.
//!
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use sha3::{Digest, Keccak256};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ApiKeyError {
  UnknownKey,
  NotAdmin,
  DisabledKey,
  ProtectedAdminKey,
  TokenExhausted,
  HourlyLimitExceeded,
}

#[derive(Clone, Debug)]
struct ApiKeyAccount {
  is_admin: bool,
  enabled: bool,
  tokens: u64,
  hourly_limit: u64,
  hourly_used: u64,
  hour_epoch: u64,
}

impl ApiKeyAccount {
  fn new_admin(hour_epoch: u64) -> Self {
    Self {
      is_admin: true,
      enabled: true,
      tokens: u64::MAX,
      hourly_limit: u64::MAX,
      hourly_used: 0,
      hour_epoch,
    }
  }

  fn new_client(hour_epoch: u64) -> Self {
    Self { is_admin: false, enabled: true, tokens: 0, hourly_limit: 0, hourly_used: 0, hour_epoch }
  }

  fn refresh_hour(&mut self, current_hour: u64) {
    if self.hour_epoch != current_hour {
      self.hour_epoch = current_hour;
      self.hourly_used = 0;
    }
  }

  fn consume_request(&mut self) -> Result<(), ApiKeyError> {
    if self.tokens == 0 {
      return Err(ApiKeyError::TokenExhausted);
    }
    if self.hourly_used >= self.hourly_limit {
      return Err(ApiKeyError::HourlyLimitExceeded);
    }
    self.tokens = self.tokens.saturating_sub(1);
    self.hourly_used = self.hourly_used.saturating_add(1);
    Ok(())
  }
}

#[derive(Clone, Debug)]
pub struct ApiKeyController {
  admin_key: String,
  keys: HashMap<String, ApiKeyAccount>,
}

impl ApiKeyController {
  pub fn new(admin_key: String) -> Self {
    let current_hour = current_hour_epoch();
    let mut keys = HashMap::new();
    keys.insert(admin_key.clone(), ApiKeyAccount::new_admin(current_hour));
    Self { admin_key, keys }
  }

  pub fn create_key(&mut self) -> String {
    loop {
      let candidate = generate_api_key(&self.admin_key);
      if !self.keys.contains_key(&candidate) {
        self.keys.insert(candidate.clone(), ApiKeyAccount::new_client(current_hour_epoch()));
        return candidate;
      }
    }
  }

  pub fn add_tokens(&mut self, key: &str, tokens: u64) -> Result<(), ApiKeyError> {
    let account = self.keys.get_mut(key).ok_or(ApiKeyError::UnknownKey)?;
    if account.is_admin {
      return Ok(());
    }
    account.tokens = account.tokens.saturating_add(tokens);
    Ok(())
  }

  pub fn set_hourly_limit(&mut self, key: &str, hourly_limit: u64) -> Result<(), ApiKeyError> {
    let account = self.keys.get_mut(key).ok_or(ApiKeyError::UnknownKey)?;
    if account.is_admin {
      return Ok(());
    }
    account.hourly_limit = hourly_limit;
    Ok(())
  }

  pub fn disable_key(&mut self, key: &str) -> Result<(), ApiKeyError> {
    if key == self.admin_key {
      return Err(ApiKeyError::ProtectedAdminKey);
    }
    let account = self.keys.get_mut(key).ok_or(ApiKeyError::UnknownKey)?;
    account.enabled = false;
    Ok(())
  }

  pub fn delete_key(&mut self, key: &str) -> Result<(), ApiKeyError> {
    if key == self.admin_key {
      return Err(ApiKeyError::ProtectedAdminKey);
    }
    self.keys.remove(key).map(|_| ()).ok_or(ApiKeyError::UnknownKey)
  }

  pub fn authorize_public_request(&mut self, key: &str) -> Result<(), ApiKeyError> {
    let account = self.keys.get_mut(key).ok_or(ApiKeyError::UnknownKey)?;
    if !account.enabled {
      return Err(ApiKeyError::DisabledKey);
    }
    if account.is_admin {
      return Ok(());
    }
    account.refresh_hour(current_hour_epoch());
    account.consume_request()
  }

  pub fn authorize_admin_request(&mut self, key: &str) -> Result<(), ApiKeyError> {
    let account = self.keys.get_mut(key).ok_or(ApiKeyError::UnknownKey)?;
    if !account.enabled {
      return Err(ApiKeyError::DisabledKey);
    }
    if !account.is_admin || key != self.admin_key {
      return Err(ApiKeyError::NotAdmin);
    }
    Ok(())
  }
}

fn current_hour_epoch() -> u64 {
  SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs().saturating_div(3600)
}

fn generate_api_key(seed: &str) -> String {
  static KEY_COUNTER: AtomicU64 = AtomicU64::new(0);
  let mut hasher = Keccak256::new();
  let count = KEY_COUNTER.fetch_add(1, Ordering::Relaxed);
  let now_ns =
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos().to_le_bytes();
  hasher.update(seed.as_bytes());
  hasher.update(now_ns);
  hasher.update(count.to_le_bytes());
  format!("olabs-api-{}", hex::encode(hasher.finalize()))
}
