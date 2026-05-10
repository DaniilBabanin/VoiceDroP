#!/usr/bin/env bash
# Local build script for VoiceDrop.
# Usage: ./scripts/build-local.sh [clean|debug|release|test|all]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$ROOT_DIR"

MODE="${1:-debug}"

run_gradle() {
    ./gradlew "$@" --stacktrace
}

case "$MODE" in
  clean)
    echo "==> Cleaning..."
    run_gradle clean
    ;;
  debug)
    echo "==> Building debug APK..."
    run_gradle assembleDebug
    echo ""
    echo "APK: app/build/outputs/apk/debug/app-debug.apk"
    ;;
  release)
    if [[ -z "${KEYSTORE_PATH:-}" ]]; then
      echo "ERROR: Set KEYSTORE_PATH, KEY_ALIAS, KEY_PASSWORD, STORE_PASSWORD env vars for release build."
      exit 1
    fi
    echo "==> Building release APK..."
    run_gradle assembleRelease \
      -Pandroid.injected.signing.store.file="$KEYSTORE_PATH" \
      -Pandroid.injected.signing.store.password="$STORE_PASSWORD" \
      -Pandroid.injected.signing.key.alias="$KEY_ALIAS" \
      -Pandroid.injected.signing.key.password="$KEY_PASSWORD"
    echo ""
    echo "APK: app/build/outputs/apk/release/app-release.apk"
    ;;
  test)
    echo "==> Running unit tests..."
    run_gradle testDebugUnitTest
    echo ""
    echo "Results: app/build/reports/tests/testDebugUnitTest/index.html"
    ;;
  lint)
    echo "==> Running lint..."
    run_gradle lintDebug
    echo ""
    echo "Results: app/build/reports/lint-results-debug.html"
    ;;
  all)
    echo "==> Running full check: lint + test + debug build..."
    run_gradle lintDebug testDebugUnitTest assembleDebug
    echo ""
    echo "Done. APK: app/build/outputs/apk/debug/app-debug.apk"
    ;;
  *)
    echo "Usage: $0 [clean|debug|release|test|lint|all]"
    exit 1
    ;;
esac
