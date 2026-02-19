#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="$SCRIPT_DIR/out"
mkdir -p "$OUT_DIR"

# shellcheck source=/dev/null
source "$SCRIPT_DIR/gp_env.sh"

STAMP="$(date +%Y%m%d_%H%M%S)"
REMOVE_LOG="$OUT_DIR/gp_uninstall_${STAMP}.log"
POST_LOG="$OUT_DIR/gp_post_uninstall_${STAMP}.log"

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

{
  delete_aid "applet" "$GP_APPLET_AID"
  delete_aid "package" "$GP_PACKAGE_AID"
} >"$REMOVE_LOG" 2>&1

echo "[uninstall] Capturing post-uninstall listing -> $POST_LOG"
gp "${GP_COMMON_OPTS[@]}" -l >"$POST_LOG" 2>&1

echo "[uninstall] Success. Logs:"
echo "  remove: $REMOVE_LOG"
echo "  post  : $POST_LOG"
