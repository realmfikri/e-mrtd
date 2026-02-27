#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# shellcheck source=/dev/null
source "$SCRIPT_DIR/gp_env.sh"

GP_BIN="${GP_BIN:-gp}"
WRITE_CHUNK_SIZE="${WRITE_CHUNK_SIZE:-200}"

COM_PATH_DEFAULT="$REPO_ROOT/card-applet/sample-data/passport/EF.COM.bin"
DG1_PATH_DEFAULT="$REPO_ROOT/card-applet/sample-data/passport/EF.DG1.bin"
DG2_PATH_DEFAULT="$REPO_ROOT/card-applet/sample-data/passport/EF.DG2.bin"

DOC_NUMBER="${DOC_NUMBER:-C4X9L2Q7}"
DOB="${DOB:-030211}"
DOE="${DOE:-280211}"
COM_PATH="${COM_PATH:-$COM_PATH_DEFAULT}"
DG1_PATH="${DG1_PATH:-$DG1_PATH_DEFAULT}"
DG2_PATH="${DG2_PATH:-$DG2_PATH_DEFAULT}"
WITH_DG2=0

usage() {
  cat <<'USAGE'
Usage: card-applet/tools/personalize_passport.sh [options]

Options:
  --doc-number <value>   MRZ document number (auto-padded to 9 chars with '<')
  --dob <YYMMDD>         Date of birth for BAC seed
  --doe <YYMMDD>         Date of expiry for BAC seed
  --com <path>           EF.COM binary (default: sample-data/passport/EF.COM.bin)
  --dg1 <path>           EF.DG1 binary (default: sample-data/passport/EF.DG1.bin)
  --with-dg2             Also write EF.DG2 from --dg2 (or default sample)
  --dg2 <path>           EF.DG2 binary path
  -h, --help             Show this help

Environment:
  APPLET_PROFILE must resolve to 'passport' (default via gp_env.sh).
  GP_READER, GP_EXTRA_OPTS, GP_NFC_BLOCK_SIZE are honored via gp_env.sh.
USAGE
}

while (( $# > 0 )); do
  case "$1" in
    --doc-number)
      DOC_NUMBER="$2"
      shift 2
      ;;
    --dob)
      DOB="$2"
      shift 2
      ;;
    --doe)
      DOE="$2"
      shift 2
      ;;
    --com)
      COM_PATH="$2"
      shift 2
      ;;
    --dg1)
      DG1_PATH="$2"
      shift 2
      ;;
    --with-dg2)
      WITH_DG2=1
      shift
      ;;
    --dg2)
      DG2_PATH="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "ERROR: unknown option '$1'" >&2
      usage
      exit 1
      ;;
  esac
done

if [[ "$APPLET_PROFILE" != "passport" ]]; then
  echo "ERROR: APPLET_PROFILE must be 'passport' for this script (current: $APPLET_PROFILE)" >&2
  exit 1
fi

if ! command -v "$GP_BIN" >/dev/null 2>&1; then
  echo "ERROR: gp not found in PATH (set GP_BIN if needed)." >&2
  exit 1
fi

for f in "$COM_PATH" "$DG1_PATH"; do
  if [[ ! -f "$f" ]]; then
    echo "ERROR: required file not found: $f" >&2
    exit 1
  fi
done

if (( WITH_DG2 == 1 )) && [[ ! -f "$DG2_PATH" ]]; then
  echo "ERROR: DG2 file not found: $DG2_PATH" >&2
  exit 1
fi

if (( WRITE_CHUNK_SIZE <= 0 || WRITE_CHUNK_SIZE > 255 )); then
  echo "ERROR: WRITE_CHUNK_SIZE must be between 1 and 255." >&2
  exit 1
fi

DOB="$(printf '%s' "$DOB" | tr -d '[:space:]')"
DOE="$(printf '%s' "$DOE" | tr -d '[:space:]')"

if [[ ! "$DOB" =~ ^[0-9]{6}$ ]]; then
  echo "ERROR: DOB must be YYMMDD (6 digits)." >&2
  exit 1
fi
if [[ ! "$DOE" =~ ^[0-9]{6}$ ]]; then
  echo "ERROR: DOE must be YYMMDD (6 digits)." >&2
  exit 1
fi

DOC_NUMBER="$(printf '%s' "$DOC_NUMBER" | tr -d '[:space:]' | tr '[:lower:]' '[:upper:]')"
if (( ${#DOC_NUMBER} > 9 )); then
  echo "ERROR: doc number too long for TD3 MRZ (max 9 chars)." >&2
  exit 1
fi
while (( ${#DOC_NUMBER} < 9 )); do
  DOC_NUMBER="${DOC_NUMBER}<"
done

hex_ascii() {
  printf '%s' "$1" | xxd -p -c 999 | tr -d '\n' | tr '[:lower:]' '[:upper:]'
}

hex_file_chunk() {
  local path="$1"
  local offset="$2"
  local count="$3"
  dd if="$path" bs=1 skip="$offset" count="$count" status=none | xxd -p -c "$count" | tr -d '\n' | tr '[:lower:]' '[:upper:]'
}

extract_sw() {
  local output="$1"
  local resp
  resp="$(printf '%s\n' "$output" | awk '
    $1=="A<<" {
      line=$0
      sub(/^.*[)] /, "", line)
      gsub(/ /, "", line)
      last=line
    }
    END {
      if (length(last) >= 4) {
        print substr(last, length(last) - 3)
      }
    }
  ')"
  printf '%s' "$resp"
}

run_gp_apdu() {
  local label="$1"
  local apdu="$2"
  local expect_sw="${3:-9000}"
  local tx="$apdu"
  local output sw

  if (( ${#tx} > 10 )); then
    tx="${tx}00"
  fi

  if ! output="$("$GP_BIN" --debug --verbose "${GP_COMMON_OPTS[@]}" -a "$tx" 2>&1)"; then
    echo "ERROR: APDU command failed: $label" >&2
    echo "$output" >&2
    exit 1
  fi

  sw="$(extract_sw "$output")"
  if [[ -z "$sw" ]]; then
    echo "ERROR: unable to parse SW for APDU: $label" >&2
    echo "$output" >&2
    exit 1
  fi

  echo "[perso] $label -> SW=$sw"
  if [[ "$sw" != "$expect_sw" ]]; then
    echo "ERROR: expected SW=$expect_sw, got SW=$sw ($label)" >&2
    exit 1
  fi
}

create_ef() {
  local fid="$1"
  local size="$2"
  local label="$3"
  local size_hex

  if (( size <= 0 || size > 65535 )); then
    echo "ERROR: invalid EF size for $label: $size" >&2
    exit 1
  fi

  size_hex="$(printf '%04X' "$size")"
  run_gp_apdu "$label" "00E00000066304${size_hex}${fid}" "9000"
}

select_ef() {
  local fid="$1"
  run_gp_apdu "SELECT EF ${fid}" "00A4020C02${fid}" "9000"
}

write_binary_file() {
  local path="$1"
  local label="$2"
  local size offset remaining take off_hex lc_hex data_hex

  size="$(wc -c < "$path" | tr -d ' ')"
  if (( size <= 0 )); then
    echo "ERROR: file is empty: $path" >&2
    exit 1
  fi

  offset=0
  while (( offset < size )); do
    remaining=$(( size - offset ))
    take=$WRITE_CHUNK_SIZE
    if (( take > remaining )); then
      take=$remaining
    fi

    off_hex="$(printf '%04X' "$offset")"
    lc_hex="$(printf '%02X' "$take")"
    data_hex="$(hex_file_chunk "$path" "$offset" "$take")"
    run_gp_apdu "${label} (offset=${offset}, len=${take})" "00D6${off_hex}${lc_hex}${data_hex}" "9000"
    offset=$(( offset + take ))
  done
}

doc_hex="$(hex_ascii "$DOC_NUMBER")"
dob_hex="$(hex_ascii "$DOB")"
doe_hex="$(hex_ascii "$DOE")"
mrz_inner="5F1F09${doc_hex}5F1806${dob_hex}5F1906${doe_hex}"
mrz_data="62$(printf '%02X' $(( ${#mrz_inner} / 2 )))${mrz_inner}"
mrz_lc="$(printf '%02X' $(( ${#mrz_data} / 2 )))"

aid_lc="$(printf '%02X' $(( ${#APPLET_AID_HEX} / 2 )))"
run_gp_apdu "SELECT applet AID ${APPLET_AID_HEX}" "00A40400${aid_lc}${APPLET_AID_HEX}" "9000"

com_size="$(wc -c < "$COM_PATH" | tr -d ' ')"
dg1_size="$(wc -c < "$DG1_PATH" | tr -d ' ')"
create_ef "011E" "$com_size" "CREATE EF.COM (011E)"
select_ef "011E"
write_binary_file "$COM_PATH" "WRITE EF.COM"

create_ef "0101" "$dg1_size" "CREATE EF.DG1 (0101)"
select_ef "0101"
write_binary_file "$DG1_PATH" "WRITE EF.DG1"

if (( WITH_DG2 == 1 )); then
  dg2_size="$(wc -c < "$DG2_PATH" | tr -d ' ')"
  create_ef "0102" "$dg2_size" "CREATE EF.DG2 (0102)"
  select_ef "0102"
  write_binary_file "$DG2_PATH" "WRITE EF.DG2"
fi

run_gp_apdu "PUT DATA MRZ seed" "00DA0062${mrz_lc}${mrz_data}" "9000"

files_written="EF.COM, EF.DG1"
if (( WITH_DG2 == 1 )); then
  files_written+=", EF.DG2"
fi

echo "[perso] Completed."
echo "[perso] MRZ seed: DOC=${DOC_NUMBER} DOB=${DOB} DOE=${DOE}"
echo "[perso] Files written: ${files_written}"
