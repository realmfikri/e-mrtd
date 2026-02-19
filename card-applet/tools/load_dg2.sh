#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# shellcheck source=/dev/null
source "$SCRIPT_DIR/gp_env.sh"

GP_BIN="${GP_BIN:-gp}"
APPLET_AID_HEX="${APPLET_AID_HEX:-A000000247100001}"
DG2_DF_FID="${DG2_DF_FID:-1100}"
DG2_EF_FID="${DG2_EF_FID:-0102}"
DG2_CHUNK_SIZE="${DG2_CHUNK_SIZE:-200}"
DG2_PATH_DEFAULT="$REPO_ROOT/card-applet/sample-data/DG2/fikri jamal.jpeg"
DG2_PATH="${1:-${DG2_PATH:-$DG2_PATH_DEFAULT}}"

if ! command -v "$GP_BIN" >/dev/null 2>&1; then
  echo "ERROR: gp not found in PATH (set GP_BIN if needed)."
  exit 1
fi
if [[ ! -f "$DG2_PATH" ]]; then
  echo "ERROR: DG2 source file not found: $DG2_PATH"
  exit 1
fi
if (( DG2_CHUNK_SIZE <= 0 || DG2_CHUNK_SIZE > 255 )); then
  echo "ERROR: DG2_CHUNK_SIZE must be between 1 and 255."
  exit 1
fi

filesize="$(wc -c < "$DG2_PATH" | tr -d ' ')"
if (( filesize <= 0 )); then
  echo "ERROR: DG2 file is empty"
  exit 1
fi
if (( filesize > 65535 )); then
  echo "ERROR: DG2 file too large for short APDU provisioning: $filesize bytes"
  exit 1
fi

echo "[dg2] Source: $DG2_PATH ($filesize bytes)"

APDUS=()
LABELS=()
EXPECT_SW=()

add_apdu() {
  local label="$1"
  local apdu="$2"
  local expect="$3"
  APDUS+=("$apdu")
  LABELS+=("$label")
  EXPECT_SW+=("$expect")
}

# Keep printed APDU canonical while normalizing gp input for case-3 compatibility.
gp_apdu() {
  local apdu="$1"
  if (( ${#apdu} > 10 )); then
    printf '%s00' "$apdu"
  else
    printf '%s' "$apdu"
  fi
}

sw_allowed() {
  local sw="$1"
  local csv="$2"
  local IFS=','
  local v
  for v in $csv; do
    if [[ "$sw" == "$v" ]]; then
      return 0
    fi
  done
  return 1
}

add_apdu "SELECT applet" "00A4040008${APPLET_AID_HEX}" "9000"
add_apdu "SELECT MF" "00A4000C023F00" "9000"
add_apdu "CREATE DF ${DG2_DF_FID}" "00E00000078302${DG2_DF_FID}820138" "9000,6A80"
add_apdu "SELECT DF ${DG2_DF_FID}" "00A4020C02${DG2_DF_FID}" "9000"

size_hex="$(printf '%04X' "$filesize")"
add_apdu "CREATE EF ${DG2_EF_FID} size=${filesize}" "00E000000B8302${DG2_EF_FID}8201018002${size_hex}" "9000,6A80"
add_apdu "SELECT EF ${DG2_EF_FID}" "00A4020C02${DG2_EF_FID}" "9000"

offset=0
while (( offset < filesize )); do
  remaining=$(( filesize - offset ))
  take=$DG2_CHUNK_SIZE
  if (( take > remaining )); then
    take=$remaining
  fi

  off_hex="$(printf '%04X' "$offset")"
  lc_hex="$(printf '%02X' "$take")"
  data_hex="$(dd if="$DG2_PATH" bs=1 skip="$offset" count="$take" status=none | xxd -p -c "$take" | tr -d '\n')"

  add_apdu "UPDATE BINARY offset=${offset} len=${take}" "00D6${off_hex}${lc_hex}${data_hex}" "9000"
  offset=$(( offset + take ))
done

# Verify JPEG SOI marker.
add_apdu "READ BINARY verify head (16 bytes)" "00B0000010" "9000"

# Build gp command.
gp_args=(--debug --verbose "${GP_COMMON_OPTS[@]}")
for a in "${APDUS[@]}"; do
  gp_args+=(-a "$(gp_apdu "$a")")
done

if ! output="$($GP_BIN "${gp_args[@]}" 2>&1)"; then
  echo "ERROR: gp APDU batch failed"
  printf '%s\n' "$output"
  exit 1
fi

pairs="$(printf '%s\n' "$output" | awk '
  $1=="A>>" { cmd=$0; sub(/^.*[)] /, "", cmd); gsub(/ /, "", cmd); last_cmd=cmd; next }
  $1=="A<<" && last_cmd!="" { resp=$0; sub(/^.*[)] /, "", resp); gsub(/ /, "", resp); print last_cmd, resp; last_cmd=""; next }
')"

mapfile -t pair_lines < <(printf '%s\n' "$pairs")
if (( ${#pair_lines[@]} < ${#APDUS[@]} )); then
  echo "ERROR: expected at least ${#APDUS[@]} APDU responses, got ${#pair_lines[@]}"
  printf '%s\n' "$output"
  exit 1
fi

for i in "${!APDUS[@]}"; do
  label="${LABELS[$i]}"
  apdu="${APDUS[$i]}"
  expected="${EXPECT_SW[$i]}"
  resp="$(printf '%s\n' "${pair_lines[$i]}" | awk '{print $2}')"

  if (( ${#resp} < 4 )); then
    echo "ERROR: response too short for: $label"
    echo "RESP : $resp"
    exit 1
  fi

  sw="${resp: -4}"
  data="${resp:0:${#resp}-4}"

  echo "[dg2] $label"
  if [[ "$label" == UPDATE\ BINARY* ]]; then
    echo "[dg2] APDU: <omitted chunk payload>"
  else
    echo "[dg2] APDU: $apdu"
  fi
  echo "[dg2] SW  : $sw"

  if ! sw_allowed "$sw" "$expected"; then
    echo "ERROR: unexpected SW for $label. Allowed: $expected"
    echo "[dg2] DATA: ${data:-<empty>}"
    exit 1
  fi

done

echo "[dg2] DG2 upload complete to FID ${DG2_EF_FID}."
