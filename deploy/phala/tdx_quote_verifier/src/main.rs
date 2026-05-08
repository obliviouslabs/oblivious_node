use std::env;
use std::process;

use dcap_qvl::quote::{Quote, TDReport10};

#[derive(Debug, Default)]
struct Args {
  quote_hex: Option<String>,
  report_data_hex: Option<String>,
  expected_mrtd: Option<String>,
  pccs_url: Option<String>,
}

#[tokio::main]
async fn main() {
  if let Err(err) = run().await {
    eprintln!("local TDX quote verification failed: {err}");
    process::exit(1);
  }
}

async fn run() -> Result<(), String> {
  let args = parse_args()?;
  let quote_hex = args.quote_hex.ok_or_else(|| "missing --quote-hex".to_string())?;
  let report_data_hex =
    args.report_data_hex.ok_or_else(|| "missing --report-data-hex".to_string())?;

  let quote_bytes = decode_prefixed_hex(&quote_hex, "quote")?;
  let expected_report_data = decode_prefixed_hex(&report_data_hex, "report data")?;
  if expected_report_data.len() > 64 {
    return Err("report data must be at most 64 bytes".to_string());
  }

  let parsed_quote =
    Quote::parse(&quote_bytes).map_err(|err| format!("quote parse failed: {err:#}"))?;
  let parsed_td_report =
    parsed_quote.report.as_td10().ok_or_else(|| "quote is not a TDX TD report".to_string())?;
  verify_report_data(&parsed_td_report.report_data, &expected_report_data)?;

  let verified =
    dcap_qvl::collateral::get_collateral_and_verify(&quote_bytes, args.pccs_url.as_deref())
      .await
      .map_err(|err| format!("quote signature/collateral verification failed: {err:#}"))?;
  let td_report =
    verified.report.as_td10().ok_or_else(|| "verified report is not TDX".to_string())?;
  validate_tdx_tcb(td_report)?;

  if let Some(expected_mrtd) = args.expected_mrtd {
    let expected = decode_prefixed_hex(&expected_mrtd, "expected MRTD")?;
    if expected.as_slice() != td_report.mr_td.as_slice() {
      return Err(format!(
        "MRTD mismatch: got {}, expected {}",
        prefixed_hex(&td_report.mr_td),
        prefixed_hex(&expected)
      ));
    }
  }

  let body = serde_json::json!({
    "verified": true,
    "tee_type": "TEE_TDX",
    "tcb_status": verified.status,
    "advisory_ids": verified.advisory_ids,
    "reportdata": prefixed_hex(&td_report.report_data),
    "mrtd": prefixed_hex(&td_report.mr_td),
    "rtmr0": prefixed_hex(&td_report.rt_mr0),
    "rtmr1": prefixed_hex(&td_report.rt_mr1),
    "rtmr2": prefixed_hex(&td_report.rt_mr2),
    "rtmr3": prefixed_hex(&td_report.rt_mr3),
  });
  println!("{}", serde_json::to_string_pretty(&body).map_err(|err| err.to_string())?);
  Ok(())
}

fn parse_args() -> Result<Args, String> {
  let mut args = Args::default();
  let mut iter = env::args().skip(1);
  while let Some(arg) = iter.next() {
    match arg.as_str() {
      "--quote-hex" => {
        args.quote_hex =
          Some(iter.next().ok_or_else(|| "missing value for --quote-hex".to_string())?);
      }
      "--report-data-hex" => {
        args.report_data_hex =
          Some(iter.next().ok_or_else(|| "missing value for --report-data-hex".to_string())?);
      }
      "--expected-mrtd" => {
        args.expected_mrtd =
          Some(iter.next().ok_or_else(|| "missing value for --expected-mrtd".to_string())?);
      }
      "--pccs-url" => {
        args.pccs_url =
          Some(iter.next().ok_or_else(|| "missing value for --pccs-url".to_string())?);
      }
      "--help" | "-h" => {
        println!(
          "Usage: tdx_quote_verifier --quote-hex <hex> --report-data-hex <hex> [--expected-mrtd <hex>] [--pccs-url <url>]"
        );
        process::exit(0);
      }
      _ => return Err(format!("unknown argument: {arg}")),
    }
  }
  Ok(args)
}

fn validate_tdx_tcb(report: &TDReport10) -> Result<(), String> {
  if report.td_attributes[0] & 0x01 != 0 {
    return Err("TDX debug mode is not allowed".to_string());
  }
  if report.mr_signer_seam != [0u8; 48] {
    return Err("TDX mr_signer_seam is not zero".to_string());
  }
  Ok(())
}

fn verify_report_data(actual: &[u8; 64], expected_prefix: &[u8]) -> Result<(), String> {
  if &actual[..expected_prefix.len()] != expected_prefix {
    return Err(format!(
      "reportData mismatch: got {}, expected prefix {}",
      prefixed_hex(actual),
      prefixed_hex(expected_prefix)
    ));
  }
  if actual[expected_prefix.len()..].iter().any(|byte| *byte != 0) {
    return Err(format!(
      "reportData has non-zero bytes after expected prefix: {}",
      prefixed_hex(actual)
    ));
  }
  Ok(())
}

fn decode_prefixed_hex(value: &str, field: &str) -> Result<Vec<u8>, String> {
  let raw = value.strip_prefix("0x").unwrap_or(value);
  if raw.len() % 2 != 0 {
    return Err(format!("{field} hex must contain an even number of characters"));
  }
  hex::decode(raw).map_err(|err| format!("invalid {field} hex: {err}"))
}

fn prefixed_hex(bytes: &[u8]) -> String {
  format!("0x{}", hex::encode(bytes))
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn report_data_allows_zero_padded_prefix() {
    let mut actual = [0u8; 64];
    actual[..3].copy_from_slice(&[1, 2, 3]);
    verify_report_data(&actual, &[1, 2, 3]).unwrap();
  }

  #[test]
  fn report_data_rejects_wrong_prefix() {
    let actual = [0u8; 64];
    assert!(verify_report_data(&actual, &[1]).is_err());
  }

  #[test]
  fn report_data_rejects_nonzero_tail() {
    let mut actual = [0u8; 64];
    actual[2] = 7;
    assert!(verify_report_data(&actual, &[0, 0]).is_err());
  }

  #[test]
  fn tcb_rejects_debug_mode() {
    let mut report = TDReport10 {
      tee_tcb_svn: [0u8; 16],
      mr_seam: [0u8; 48],
      mr_signer_seam: [0u8; 48],
      seam_attributes: [0u8; 8],
      td_attributes: [0u8; 8],
      xfam: [0u8; 8],
      mr_td: [0u8; 48],
      mr_config_id: [0u8; 48],
      mr_owner: [0u8; 48],
      mr_owner_config: [0u8; 48],
      rt_mr0: [0u8; 48],
      rt_mr1: [0u8; 48],
      rt_mr2: [0u8; 48],
      rt_mr3: [0u8; 48],
      report_data: [0u8; 64],
    };
    report.td_attributes[0] = 1;
    assert!(validate_tdx_tcb(&report).is_err());
  }
}
