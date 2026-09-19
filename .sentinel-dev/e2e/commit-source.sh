#!/usr/bin/env bash
set -euo pipefail

ROOT=$(git rev-parse --show-toplevel 2>/dev/null) || { echo 'Run inside the KubeOps Sentinel Git repository' >&2; exit 2; }
cd -- "$ROOT"
SOURCE=KubeOps_Sentinel.sh
OUT_DIR=sentinel-output/validation
MESSAGE=${SNTL_COMMIT_MESSAGE:-"chore: validate KubeOps Sentinel source"}
mkdir -p -- "$OUT_DIR"

bash -n "$SOURCE"
TERM=dumb bash "$SOURCE" --dev-self-test --output ./sentinel-output
git diff --check -- "$SOURCE"
git add --chmod=+x -- "$SOURCE"
git diff --cached --check
git diff --cached --stat

git diff --cached --quiet && { echo 'No staged KubeOps Sentinel changes to commit'; exit 0; }
git commit -m "$MESSAGE"
git rev-parse HEAD > "$OUT_DIR/source-commit.txt"
sha256sum "$SOURCE" > "$OUT_DIR/source-sha256.txt"
printf 'Committed tested source: %s\n' "$(git rev-parse HEAD)"
