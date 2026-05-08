#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "Usage: $0 <quote-hex-or-file> [expected-mrtd]" >&2
  exit 1
fi

if ! command -v curl >/dev/null 2>&1; then
  echo "curl is required" >&2
  exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required" >&2
  exit 1
fi

INPUT="$1"
EXPECTED_MRTD="${2:-}"

if [[ -f "$INPUT" ]]; then
  QUOTE_HEX="$(tr -d ' \n\r\t' < "$INPUT")"
else
  QUOTE_HEX="$(printf '%s' "$INPUT" | tr -d ' \n\r\t')"
fi

QUOTE_HEX="${QUOTE_HEX#0x}"

if [[ ! "$QUOTE_HEX" =~ ^[0-9a-fA-F]+$ ]]; then
  echo "quote must be hex string or a file containing hex" >&2
  exit 1
fi

PAYLOAD="$(jq -n --arg hex "$QUOTE_HEX" '{hex: $hex}')"

VERIFY_API="${PHALA_ATTESTATION_VERIFY_API:-https://cloud-api.phala.com/api/v1/attestations/verify}"
VIEW_API_BASE="${PHALA_ATTESTATION_VIEW_API_BASE:-https://cloud-api.phala.com/api/v1/attestations/view}"

RESP="$(curl -fsS -X POST "$VERIFY_API" \
  -H "Content-Type: application/json" \
  -d "$PAYLOAD")"

VERIFIED="$(printf '%s' "$RESP" | jq -r '.quote.verified')"
TEE_TYPE="$(printf '%s' "$RESP" | jq -r '.quote.header.tee_type')"
MRTD="$(printf '%s' "$RESP" | jq -r '.quote.body.mrtd')"
CHECKSUM="$(printf '%s' "$RESP" | jq -r '.checksum')"

if [[ "$VERIFIED" != "true" ]]; then
  echo "attestation verify failed: quote.verified != true" >&2
  exit 1
fi

if [[ "$TEE_TYPE" != "TEE_TDX" ]]; then
  echo "unexpected tee_type: $TEE_TYPE (expected TEE_TDX)" >&2
  exit 1
fi

if [[ -n "$EXPECTED_MRTD" ]]; then
  MRTD_LOWER="$(printf '%s' "$MRTD" | tr '[:upper:]' '[:lower:]')"
  EXPECTED_LOWER="$(printf '%s' "$EXPECTED_MRTD" | tr '[:upper:]' '[:lower:]')"
  EXPECTED_LOWER="${EXPECTED_LOWER#0x}"
  MRTD_NOPFX="${MRTD_LOWER#0x}"
  if [[ "$MRTD_NOPFX" != "$EXPECTED_LOWER" ]]; then
    echo "mrtd mismatch: got $MRTD expected 0x$EXPECTED_LOWER" >&2
    exit 1
  fi
fi

printf '%s\n' "$RESP" | jq '{
  verified: .quote.verified,
  tee_type: .quote.header.tee_type,
  checksum: .checksum,
  mrtd: .quote.body.mrtd,
  rtmr0: .quote.body.rtmr0,
  rtmr1: .quote.body.rtmr1,
  rtmr2: .quote.body.rtmr2,
  rtmr3: .quote.body.rtmr3,
  reportdata: .quote.body.reportdata
}'

echo "Attestation OK. View full quote: $VIEW_API_BASE/$CHECKSUM"
