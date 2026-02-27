#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "$SCRIPT_DIR/gp_env.sh"

GP_BIN="${GP_BIN:-gp}"
OPENSC_TOOL_BIN="${OPENSC_TOOL_BIN:-opensc-tool}"
OPENSC_READER="${OPENSC_READER:-}"

APPLET_AID_HEX="${APPLET_AID_HEX}"

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
  local label="$1"
  local apdu="$2"
  local expect_sw="${3:-}"
  local expect_data="${4:-}"
  local tx output resp sw data

  tx="$apdu"
  if (( ${#tx} > 10 )); then
    tx="${tx}00"
  fi

  if ! output="$($GP_BIN --debug --verbose "${GP_COMMON_OPTS[@]}" -a "$tx" 2>&1)"; then
    echo "ERROR: gp APDU failed: $label"
    printf '%s\n' "$output"
    return 1
  fi

  resp="$(printf '%s\n' "$output" | awk -v target="$tx" '
    $1=="A>>" {
      cmd=$0
      sub(/^.*[)] /, "", cmd)
      gsub(/ /, "", cmd)
      cur_cmd=cmd
      next
    }
    $1=="A<<" {
      r=$0
      sub(/^.*[)] /, "", r)
      gsub(/ /, "", r)
      if (cur_cmd == target) {
        found=r
      }
      next
    }
    END {
      if (length(found) > 0) {
        print found
      }
    }
  ')"

  if [[ -z "$resp" ]]; then
    echo "ERROR: unable to parse response for APDU: $label ($tx)"
    printf '%s\n' "$output"
    return 1
  fi
  if (( ${#resp} < 4 )); then
    echo "ERROR: response too short for APDU: $label ($tx)"
    echo "RESP : $resp"
    return 1
  fi

  sw="${resp: -4}"
  data="${resp:0:${#resp}-4}"
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
  if [[ "${APPLET_PROFILE}" == "passport" ]]; then
    APDUS=(
      "00A4040007${APPLET_AID_HEX}"
      "00A4020C02011E"
      "00B0000020"
      "00A4020C020101"
      "00B0000020"
      "00DA006220621E5F1F09433458394C3251373C5F18063033303231315F1906323830323131"
      "0084000008"
      "00A4020C02DEAD"
    )
    LABELS=(
      "SELECT applet by AID"
      "SELECT EF.COM (011E)"
      "READ EF.COM first 32 bytes"
      "SELECT EF.DG1 (0101)"
      "READ EF.DG1 first 32 bytes"
      "PUT DATA MRZ seed (p1=00 p2=62)"
      "GET CHALLENGE (8 bytes)"
      "SELECT unknown FID (expect not found)"
    )
    EXPECT_SW=(
      "9000"
      "9000"
      "6982"
      "9000"
      "6982"
      "9000"
      "9000"
      "6A82"
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
    )
  else
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
  fi

  local -a txs gp_cmd pairs
  local tx output resp sw data pair pair_cmd pair_resp pair_idx

  gp_cmd=("$GP_BIN" --debug --verbose "${GP_COMMON_OPTS[@]}")
  txs=()
  for i in "${!APDUS[@]}"; do
    tx="${APDUS[$i]}"
    if (( ${#tx} > 10 )); then
      tx="${tx}00"
    fi
    txs+=("$tx")
    gp_cmd+=(-a "$tx")
  done

  if ! output="$("${gp_cmd[@]}" 2>&1)"; then
    echo "ERROR: gp APDU batch failed"
    printf '%s\n' "$output"
    return 1
  fi

  mapfile -t pairs < <(printf '%s\n' "$output" | awk '
    $1=="A>>" {
      cmd=$0
      sub(/^.*[)] /, "", cmd)
      gsub(/ /, "", cmd)
      cur_cmd=cmd
      next
    }
    $1=="A<<" {
      r=$0
      sub(/^.*[)] /, "", r)
      gsub(/ /, "", r)
      if (length(cur_cmd) > 0) {
        print cur_cmd "|" r
        cur_cmd=""
      }
      next
    }
  ')

  pair_idx=0
  for i in "${!APDUS[@]}"; do
    tx="${txs[$i]}"
    resp=""
    while (( pair_idx < ${#pairs[@]} )); do
      pair="${pairs[$pair_idx]}"
      pair_idx=$((pair_idx + 1))
      pair_cmd="${pair%%|*}"
      pair_resp="${pair#*|}"
      if [[ "$pair_cmd" == "$tx" ]]; then
        resp="$pair_resp"
        break
      fi
    done

    if [[ -z "$resp" ]]; then
      echo "ERROR: unable to parse response for APDU: ${LABELS[$i]} ($tx)"
      printf '%s\n' "$output"
      return 1
    fi
    if (( ${#resp} < 4 )); then
      echo "ERROR: response too short for APDU: ${LABELS[$i]} ($tx)"
      echo "RESP : $resp"
      return 1
    fi

    sw="${resp: -4}"
    data="${resp:0:${#resp}-4}"
    print_result "${LABELS[$i]}" "${APDUS[$i]}" "$data" "$sw"

    if [[ -n "${EXPECT_SW[$i]}" && "$sw" != "${EXPECT_SW[$i]}" ]]; then
      echo "ERROR: expected SW=${EXPECT_SW[$i]}, got SW=$sw (${LABELS[$i]})"
      return 1
    fi
    if [[ -n "${EXPECT_DATA[$i]}" && "$data" != "${EXPECT_DATA[$i]}" ]]; then
      echo "ERROR: expected DATA=${EXPECT_DATA[$i]}, got DATA=$data (${LABELS[$i]})"
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
if [[ "${APPLET_PROFILE}" == "passport" ]]; then
  run_apdu_opensc "SELECT applet by AID" "00A4040007${APPLET_AID_HEX}" "9000"
  run_apdu_opensc "SELECT EF.COM (011E)" "00A4020C02011E" "9000"
  run_apdu_opensc "READ EF.COM first 32 bytes" "00B0000020" "6982"
  run_apdu_opensc "SELECT EF.DG1 (0101)" "00A4020C020101" "9000"
  run_apdu_opensc "READ EF.DG1 first 32 bytes" "00B0000020" "6982"
  run_apdu_opensc "PUT DATA MRZ seed (p1=00 p2=62)" "00DA006220621E5F1F09433458394C3251373C5F18063033303231315F1906323830323131" "9000"
  run_apdu_opensc "GET CHALLENGE (8 bytes)" "0084000008" "9000"
  run_apdu_opensc "SELECT unknown FID (expect not found)" "00A4020C02DEAD" "6A82"
else
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
fi
echo "APDU smoke checks completed."
