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

{
  echo "[uninstall] Deleting applet AID: $GP_APPLET_AID"
  gp "${GP_COMMON_OPTS[@]}" -delete "$GP_APPLET_AID"
  echo "[uninstall] Deleting package AID: $GP_PACKAGE_AID"
  gp "${GP_COMMON_OPTS[@]}" -delete "$GP_PACKAGE_AID"
} >"$REMOVE_LOG" 2>&1

echo "[uninstall] Capturing post-uninstall listing -> $POST_LOG"
gp "${GP_COMMON_OPTS[@]}" -l >"$POST_LOG" 2>&1

echo "[uninstall] Success. Logs:"
echo "  remove: $REMOVE_LOG"
echo "  post  : $POST_LOG"
