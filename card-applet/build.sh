#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ -z "${JCKIT:-}" && -n "${JCPATH:-}" ]]; then
  export JCKIT="${JCPATH}"
  echo "INFO: mapped legacy JCPATH to JCKIT (${JCKIT})"
fi

if [[ -z "${JAVA_HOME:-}" ]]; then
  echo "ERROR: JAVA_HOME must be set"
  exit 1
fi

if [[ -z "${JCKIT:-}" ]]; then
  echo "ERROR: JCKIT must be set (or set legacy JCPATH)"
  exit 1
fi

make -C "${SCRIPT_DIR}" clean all

CAP_PATH="${SCRIPT_DIR}/build/applet.cap"
if [[ ! -f "${CAP_PATH}" ]]; then
  echo "ERROR: expected CAP output missing at ${CAP_PATH}"
  exit 1
fi

echo "Build successful: ${CAP_PATH}"
