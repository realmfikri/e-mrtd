#!/usr/bin/env bash
set -euo pipefail

# Shared GlobalPlatformPro configuration for this project.
# Allow reader override from caller while providing a stable default.
export GP_READER="${GP_READER:-ACR1552 1S CL Reader PICC}"

# Applet profile defaults.
export APPLET_PROFILE="${APPLET_PROFILE:-passport}"
case "$APPLET_PROFILE" in
  passport)
    DEFAULT_GP_PACKAGE_AID="A00000024710"
    DEFAULT_GP_APPLET_AID="A0000002471001"
    DEFAULT_APPLET_AID_HEX="A0000002471001"
    ;;
  educational)
    DEFAULT_GP_PACKAGE_AID="A0000002471000"
    DEFAULT_GP_APPLET_AID="A000000247100001"
    DEFAULT_APPLET_AID_HEX="A000000247100001"
    ;;
  *)
    echo "ERROR: unsupported APPLET_PROFILE='$APPLET_PROFILE' (use passport or educational)" >&2
    exit 1
    ;;
esac

# Project AIDs / artifacts.
export GP_PACKAGE_AID="${GP_PACKAGE_AID:-$DEFAULT_GP_PACKAGE_AID}"
export GP_APPLET_AID="${GP_APPLET_AID:-$DEFAULT_GP_APPLET_AID}"
export GP_CAP_REL="${GP_CAP_REL:-card-applet/build/applet.cap}"
export APPLET_AID_HEX="${APPLET_AID_HEX:-$DEFAULT_APPLET_AID_HEX}"

# NFC-friendly defaults; callers can tune with GP_NFC_BLOCK_SIZE and GP_RETRIES.
export GP_NFC_BLOCK_SIZE="${GP_NFC_BLOCK_SIZE:-128}"
export GP_RETRIES="${GP_RETRIES:-3}"
export GP_RETRY_SLEEP="${GP_RETRY_SLEEP:-1}"

# Common options reused by install/uninstall/list commands.
# Keep key and reader centralized so all scripts behave consistently.
GP_COMMON_OPTS=(
  -key default
  -reader "$GP_READER"
)

# Best effort: include block size if caller enables it and their gp supports it.
if [[ -n "${GP_NFC_BLOCK_SIZE}" ]]; then
  GP_COMMON_OPTS+=(--bs "$GP_NFC_BLOCK_SIZE")
fi

# Allow advanced, caller-provided overrides (word splitting intentional).
if [[ -n "${GP_EXTRA_OPTS:-}" ]]; then
  # shellcheck disable=SC2206
  GP_EXTRA_OPTS_ARR=(${GP_EXTRA_OPTS})
  GP_COMMON_OPTS+=("${GP_EXTRA_OPTS_ARR[@]}")
fi

export GP_COMMON_OPTS
