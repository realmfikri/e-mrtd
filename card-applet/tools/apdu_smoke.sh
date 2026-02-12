#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "$SCRIPT_DIR/gp_env.sh"

OPENSC_TOOL_BIN="${OPENSC_TOOL_BIN:-opensc-tool}"
OPENSC_READER="${OPENSC_READER:-}"

OPENSC_TOOL_ARGS=()
if [[ -n "$OPENSC_READER" ]]; then
  OPENSC_TOOL_ARGS+=(--reader "$OPENSC_READER")
fi

APPLET_AID_HEX="${APPLET_AID_HEX:-D276000124010001}"

print_result() {
  local label="$1"
  local apdu="$2"
  local data="$3"
  local sw="$4"

  echo "=== $label ==="
  echo "APDU : $apdu"
  echo "DATA : ${data:-<empty>}"
  echo "SW   : $sw"
  echo
}

run_apdu() {
  local label="$1"
  local apdu="$2"
  local expect_sw="${3:-}"

  local output response_line payload payload_hex sw data
  output="$($OPENSC_TOOL_BIN "${OPENSC_TOOL_ARGS[@]}" -s "$apdu" 2>&1)"

  response_line="$(printf '%s\n' "$output" | rg "Received" | tail -n1 || true)"
  if [[ -z "$response_line" ]]; then
    echo "ERROR: Unable to parse opensc-tool output for: $label"
    printf '%s\n' "$output"
    return 1
  fi

  payload="$(printf '%s\n' "$response_line" | sed -E 's/.*: *//')"
  payload_hex="$(printf '%s' "$payload" | tr -cd '0-9A-Fa-f')"

  if (( ${#payload_hex} < 4 )); then
    echo "ERROR: Response too short for: $label"
    printf '%s\n' "$output"
    return 1
  fi

  sw="${payload_hex: -4}"
  data="${payload_hex:0:${#payload_hex}-4}"

  print_result "$label" "$apdu" "$data" "$sw"

  if [[ -n "$expect_sw" && "$sw" != "$expect_sw" ]]; then
    echo "ERROR: expected SW=$expect_sw, got SW=$sw ($label)"
    return 1
  fi
}

# SELECT by applet AID
run_apdu "SELECT applet by AID" "00A4040008${APPLET_AID_HEX}" "9000"

# SELECT EF.COM (011E) + READ first 32 bytes
run_apdu "SELECT EF.COM (011E)" "00A4020C02011E" "9000"
run_apdu "READ EF.COM first 32 bytes" "00B0000020" "9000"

# SELECT EF.DG1 (0101) + READ first 64 bytes in two 32-byte chunks
run_apdu "SELECT EF.DG1 (0101)" "00A4020C020101" "9000"
run_apdu "READ EF.DG1 bytes [0..31]" "00B0000020" "9000"
run_apdu "READ EF.DG1 bytes [32..63]" "00B0002020" "9000"

# Negative: SELECT unknown FID -> expect 6A82
run_apdu "SELECT unknown FID (expect not found)" "00A4020C02DEAD" "6A82"

echo "APDU smoke checks completed."
