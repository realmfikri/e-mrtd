#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
OUT_DIR="$SCRIPT_DIR/out"
mkdir -p "$OUT_DIR"

# shellcheck source=/dev/null
source "$SCRIPT_DIR/gp_env.sh"

CAP_PATH="$REPO_ROOT/$GP_CAP_REL"
echo "[install] profile=$APPLET_PROFILE package_aid=$GP_PACKAGE_AID applet_aid=$GP_APPLET_AID"
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

cleanup_profile_aids() {
  local aid
  gp "${GP_COMMON_OPTS[@]}" -uninstall "$CAP_PATH" >/dev/null 2>&1 || true

  local applet_aids=("$GP_APPLET_AID" "A000000247100001" "A0000002471001")
  local package_aids=("$GP_PACKAGE_AID" "A0000002471000" "A00000024710")

  for aid in "${applet_aids[@]}"; do
    gp "${GP_COMMON_OPTS[@]}" -delete "$aid" >/dev/null 2>&1 || true
  done
  for aid in "${package_aids[@]}"; do
    gp "${GP_COMMON_OPTS[@]}" -delete "$aid" >/dev/null 2>&1 || true
  done
}

echo "[install] Capturing pre-install card listing -> $PRE_LOG"
if ! gp "${GP_COMMON_OPTS[@]}" -l >"$PRE_LOG" 2>&1; then
  echo "[install] Warning: pre-install listing failed (see $PRE_LOG)"
fi

ok=0
failure_sw=""
failure_phase=""
: >"$INSTALL_LOG"
for i in $(seq 1 "$GP_RETRIES"); do
  ATTEMPT_LOG="$OUT_DIR/gp_install_${STAMP}_attempt${i}.log"
  if attempt_gp_install "$i" >"$ATTEMPT_LOG" 2>&1; then
    cp "$ATTEMPT_LOG" "$INSTALL_LOG"
    ok=1
    break
  fi
  {
    echo "[install] Attempt ${i} failed log ($ATTEMPT_LOG):"
    cat "$ATTEMPT_LOG"
    echo
  } >>"$INSTALL_LOG"

  if grep -q "INSTALL \[for load\] failed: 0x6985" "$ATTEMPT_LOG"; then
    failure_sw="6985"
    failure_phase="install-for-load"
    echo "[install] Detected stale/blocked package state (0x6985); cleaning known profile AIDs before retry."
    cleanup_profile_aids
  elif grep -q "INSTALL \[for install and make selectable\] failed: 0x6F00" "$ATTEMPT_LOG"; then
    failure_sw="6F00"
    failure_phase="make-selectable"
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
  echo "[install] Guidance: clear previously installed profile packages with:"
  echo "          UNINSTALL_ALL_PROFILES=1 ./card-applet/tools/uninstall.sh"
  if [[ "$failure_sw" == "6F00" && "$failure_phase" == "make-selectable" ]]; then
    echo "[install] Guidance: applet constructor failed during make-selectable (0x6F00)."
    echo "[install]           This typically indicates on-card crypto/memory incompatibility in install-time initialization."
  fi
  echo "[install] Install log: $INSTALL_LOG"
  exit 1
fi

echo "[install] Capturing post-install card listing -> $POST_LOG"
gp "${GP_COMMON_OPTS[@]}" -l >"$POST_LOG" 2>&1

echo "[install] Success. Logs:"
echo "  pre : $PRE_LOG"
echo "  install: $INSTALL_LOG"
echo "  post: $POST_LOG"
