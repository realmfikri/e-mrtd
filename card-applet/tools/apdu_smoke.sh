#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "$SCRIPT_DIR/gp_env.sh"

GP_BIN="${GP_BIN:-gp}"
OPENSC_TOOL_BIN="${OPENSC_TOOL_BIN:-opensc-tool}"
OPENSC_READER="${OPENSC_READER:-}"

APPLET_AID_HEX="${APPLET_AID_HEX:-A000000247100001}"

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

run_apdu_gp() {
  echo "ERROR: internal error (run_apdu_gp should not be called)"
  exit 2
}

run_apdu_opensc() {
  local label="$1"
  local apdu="$2"
  local expect_sw="${3:-}"
  local expect_data="${4:-}"

  # Fallback: opensc-tool (needs OPENSC_READER to reliably hit the PICC reader on ACR1552).
  local opensc_args=()
  if [[ -n "$OPENSC_READER" ]]; then
    opensc_args+=(--reader "$OPENSC_READER")
  fi

  local output response_line payload payload_hex sw data
  output="$($OPENSC_TOOL_BIN "${opensc_args[@]}" -s "$apdu" 2>&1)"

  response_line="$(printf '%s\n' "$output" | rg "Received" | tail -n1 || true)"
  if [[ -z "$response_line" ]]; then
    echo "ERROR: Unable to parse output for: $label"
    echo "Tip: install GlobalPlatformPro (gp) or set OPENSC_READER to the PICC reader name from: opensc-tool -l"
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
  if [[ -n "$expect_data" && "$data" != "$expect_data" ]]; then
    echo "ERROR: expected DATA=$expect_data, got DATA=$data ($label)"
    return 1
  fi
}

run_apdus_gp() {
  local output pairs label expect resp sw data
  local -a pair_lines

  # Human-readable APDUs (without optional trailing Le for case-3 commands).
  APDUS=(
    "00A4040008${APPLET_AID_HEX}"
    "00A4020C02011E"
    "00B0000020"
    "00A4020C020101"
    "00B0000020"
    "00B0002020"
    "00A4020C02DEAD"
    "00A4000C023F00"
    "00E000000783021100820138"
    "00A4020C021100"
    "00E000000A83021101820101800140"
    "00A4020C021101"
    "00D6000010465344454D4F5F57524954455F544553"
    "00B0000010"
    "00B0001010"
  )
  LABELS=(
    "SELECT applet by AID"
    "SELECT EF.COM (011E)"
    "READ EF.COM first 32 bytes"
    "SELECT EF.DG1 (0101)"
    "READ EF.DG1 bytes [0..31]"
    "READ EF.DG1 bytes [32..63]"
    "SELECT unknown FID (expect not found)"
    "SELECT MF (3F00)"
    "CREATE DF (1100)"
    "SELECT DF (1100)"
    "CREATE EF (1101, size 0x40)"
    "SELECT EF (1101)"
    "UPDATE BINARY EF(1101) bytes [0..15]"
    "READ EF(1101) bytes [0..15]"
    "READ EF(1101) bytes [16..31] (zero-filled)"
  )
  EXPECT_SW=(
    "9000"
    "9000"
    "9000"
    "9000"
    "9000"
    "9000"
    "6A82"
    "9000"
    "9000"
    "9000"
    "9000"
    "9000"
    "9000"
    "9000"
    "9000"
  )
  EXPECT_DATA=(
    ""
    ""
    ""
    ""
    ""
    ""
    ""
    ""
    ""
    ""
    ""
    ""
    ""
    "465344454D4F5F57524954455F544553"
    "00000000000000000000000000000000"
  )

  # Some gp builds reject case-3 APDUs unless an explicit trailing Le byte is present.
  # Keep printed APDUs canonical while normalizing gp input for compatibility.
  GP_APDUS=()
  for a in "${APDUS[@]}"; do
    if (( ${#a} > 10 )); then
      GP_APDUS+=("${a}00")
    else
      GP_APDUS+=("$a")
    fi
  done

  gp_args=(--debug --verbose "${GP_COMMON_OPTS[@]}")
  for a in "${GP_APDUS[@]}"; do
    gp_args+=(-a "$a")
  done

  if ! output="$($GP_BIN "${gp_args[@]}" 2>&1)"; then
    echo "ERROR: gp APDU batch failed."
    printf '%s\n' "$output"
    return 1
  fi

  # Build a table of: <APDU_HEX_NO_SPACES> <RESP_HEX_NO_SPACES>
  pairs="$(printf '%s\n' "$output" | awk '
    $1=="A>>" { cmd=$0; sub(/^.*[)] /, "", cmd); gsub(/ /, "", cmd); last_cmd=cmd; next }
    $1=="A<<" && last_cmd!="" { resp=$0; sub(/^.*[)] /, "", resp); gsub(/ /, "", resp); print last_cmd, resp; last_cmd=""; next }
  ')"

  mapfile -t pair_lines < <(printf '%s\n' "$pairs")
  if (( ${#pair_lines[@]} < ${#APDUS[@]} )); then
    echo "ERROR: expected at least ${#APDUS[@]} APDU responses, got ${#pair_lines[@]}"
    printf '%s\n' "$output"
    return 1
  fi

  for i in "${!APDUS[@]}"; do
    label="${LABELS[$i]}"
    expect="${EXPECT_SW[$i]}"
    expect_data="${EXPECT_DATA[$i]}"

    # Use response order: gp prints A>>/A<< pairs in the same order as the -a arguments.
    resp="$(printf '%s\n' "${pair_lines[$i]}" | awk '{print $2}')"

    if (( ${#resp} < 4 )); then
      echo "ERROR: response too short for: $label"
      echo "RESP : $resp"
      return 1
    fi

    sw="${resp: -4}"
    data="${resp:0:${#resp}-4}"
    print_result "$label" "${APDUS[$i]}" "$data" "$sw"

    if [[ -n "$expect" && "$sw" != "$expect" ]]; then
      echo "ERROR: expected SW=$expect, got SW=$sw ($label)"
      return 1
    fi
    if [[ -n "$expect_data" && "$data" != "$expect_data" ]]; then
      echo "ERROR: expected DATA=$expect_data, got DATA=$data ($label)"
      return 1
    fi
  done

  echo "APDU smoke checks completed."
}

if command -v "$GP_BIN" >/dev/null 2>&1; then
  run_apdus_gp
  exit $?
fi

# No gp: try opensc-tool sequentially (state may not persist depending on reader/runtime).
run_apdu_opensc "SELECT applet by AID" "00A4040008${APPLET_AID_HEX}" "9000"
run_apdu_opensc "SELECT EF.COM (011E)" "00A4020C02011E" "9000"
run_apdu_opensc "READ EF.COM first 32 bytes" "00B0000020" "9000"
run_apdu_opensc "SELECT EF.DG1 (0101)" "00A4020C020101" "9000"
run_apdu_opensc "READ EF.DG1 bytes [0..31]" "00B0000020" "9000"
run_apdu_opensc "READ EF.DG1 bytes [32..63]" "00B0002020" "9000"
run_apdu_opensc "SELECT unknown FID (expect not found)" "00A4020C02DEAD" "6A82"
run_apdu_opensc "SELECT MF (3F00)" "00A4000C023F00" "9000"
run_apdu_opensc "CREATE DF (1100)" "00E000000783021100820138" "9000"
run_apdu_opensc "SELECT DF (1100)" "00A4020C021100" "9000"
run_apdu_opensc "CREATE EF (1101, size 0x40)" "00E000000A83021101820101800140" "9000"
run_apdu_opensc "SELECT EF (1101)" "00A4020C021101" "9000"
run_apdu_opensc "UPDATE BINARY EF(1101) bytes [0..15]" "00D6000010465344454D4F5F57524954455F544553" "9000"
run_apdu_opensc "READ EF(1101) bytes [0..15]" "00B0000010" "9000" "465344454D4F5F57524954455F544553"
run_apdu_opensc "READ EF(1101) bytes [16..31] (zero-filled)" "00B0001010" "9000" "00000000000000000000000000000000"
echo "APDU smoke checks completed."
