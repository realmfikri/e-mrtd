#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="$SCRIPT_DIR/out"
mkdir -p "$OUT_DIR"

# shellcheck source=/dev/null
source "$SCRIPT_DIR/gp_env.sh"

echo "[uninstall] profile=$APPLET_PROFILE package_aid=$GP_PACKAGE_AID applet_aid=$GP_APPLET_AID"
STAMP="$(date +%Y%m%d_%H%M%S)"
REMOVE_LOG="$OUT_DIR/gp_uninstall_${STAMP}.log"
POST_LOG="$OUT_DIR/gp_post_uninstall_${STAMP}.log"
UNINSTALL_ALL_PROFILES="${UNINSTALL_ALL_PROFILES:-1}"

delete_aid() {
  local label="$1"
  local aid="$2"
  local output

  echo "[uninstall] Deleting ${label} AID: ${aid}"
  if output="$(gp "${GP_COMMON_OPTS[@]}" -delete "$aid" 2>&1)"; then
    printf '%s\n' "$output"
    return 0
  fi

  printf '%s\n' "$output"
  if printf '%s\n' "$output" | rg -qi "not present on card|6a88"; then
    echo "[uninstall] ${label} AID not present; continuing."
    return 0
  fi

  echo "[uninstall] ERROR: failed deleting ${label} AID: ${aid}"
  return 1
}

collect_unique_aids() {
  local -n out_ref=$1
  shift
  local aid
  declare -A seen=()
  out_ref=()
  for aid in "$@"; do
    if [[ -n "$aid" && -z "${seen[$aid]:-}" ]]; then
      out_ref+=("$aid")
      seen[$aid]=1
    fi
  done
}

{
  if [[ "$UNINSTALL_ALL_PROFILES" == "1" ]]; then
    collect_unique_aids APPLET_AIDS \
      "$GP_APPLET_AID" \
      "A000000247100001" \
      "A0000002471001"
    collect_unique_aids PACKAGE_AIDS \
      "$GP_PACKAGE_AID" \
      "A0000002471000" \
      "A00000024710"
  else
    APPLET_AIDS=("$GP_APPLET_AID")
    PACKAGE_AIDS=("$GP_PACKAGE_AID")
  fi

  uninstall_failed=0

  for aid in "${APPLET_AIDS[@]}"; do
    delete_aid "applet" "$aid" || uninstall_failed=1
  done
  for aid in "${PACKAGE_AIDS[@]}"; do
    delete_aid "package" "$aid" || uninstall_failed=1
  done

  if (( uninstall_failed != 0 )); then
    echo "[uninstall] ERROR: one or more delete operations failed."
    exit 1
  fi
} >"$REMOVE_LOG" 2>&1

echo "[uninstall] Capturing post-uninstall listing -> $POST_LOG"
gp "${GP_COMMON_OPTS[@]}" -l >"$POST_LOG" 2>&1

echo "[uninstall] Success. Logs:"
echo "  remove: $REMOVE_LOG"
echo "  post  : $POST_LOG"
