#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
OUT_DIR="$SCRIPT_DIR/out"
mkdir -p "$OUT_DIR"

# shellcheck source=/dev/null
source "$SCRIPT_DIR/gp_env.sh"

CAP_PATH="$REPO_ROOT/$GP_CAP_REL"
STAMP="$(date +%Y%m%d_%H%M%S)"
PRE_LOG="$OUT_DIR/gp_pre_install_${STAMP}.log"
POST_LOG="$OUT_DIR/gp_post_install_${STAMP}.log"
INSTALL_LOG="$OUT_DIR/gp_install_${STAMP}.log"

if [[ ! -f "$CAP_PATH" ]]; then
  echo "[install] CAP not found at $CAP_PATH"
  echo "[install] Building CAP with: make -C card-applet all"
  make -C "$REPO_ROOT/card-applet" all
fi

attempt_gp_install() {
  local attempt="$1"
  echo "[install] Attempt ${attempt}/${GP_RETRIES}"
  echo "[install] NFC-friendly settings: block-size=${GP_NFC_BLOCK_SIZE}, retry-sleep=${GP_RETRY_SLEEP}s"

  gp "${GP_COMMON_OPTS[@]}" -install "$CAP_PATH"
}

echo "[install] Capturing pre-install card listing -> $PRE_LOG"
if ! gp "${GP_COMMON_OPTS[@]}" -l >"$PRE_LOG" 2>&1; then
  echo "[install] Warning: pre-install listing failed (see $PRE_LOG)"
fi

ok=0
for i in $(seq 1 "$GP_RETRIES"); do
  if attempt_gp_install "$i" >"$INSTALL_LOG" 2>&1; then
    ok=1
    break
  fi
  echo "[install] Install failed on attempt $i."
  if (( i < GP_RETRIES )); then
    echo "[install] Retrying after ${GP_RETRY_SLEEP}s..."
    sleep "$GP_RETRY_SLEEP"
  fi
done

if (( ok == 0 )); then
  echo "[install] ERROR: install failed after $GP_RETRIES attempts."
  echo "[install] Guidance: keep card stable on reader and try a smaller GP_NFC_BLOCK_SIZE (for example 96 or 64)."
  echo "[install] Install log: $INSTALL_LOG"
  exit 1
fi

echo "[install] Capturing post-install card listing -> $POST_LOG"
gp "${GP_COMMON_OPTS[@]}" -l >"$POST_LOG" 2>&1

echo "[install] Success. Logs:"
echo "  pre : $PRE_LOG"
echo "  install: $INSTALL_LOG"
echo "  post: $POST_LOG"
