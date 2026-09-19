#!/usr/bin/env bash
set -euo pipefail

ROOT=$(git rev-parse --show-toplevel 2>/dev/null || { cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P; })
IMAGE_DIR="$ROOT/.sentinel-dev/image"
OUT_DIR="$ROOT/sentinel-output/validation"
IMAGE=${SNTL_VALIDATION_IMAGE:-sentinel-runtime:validation-v1}
KUBECTL_BIN=${SNTL_KUBECTL_BIN:-$(command -v kubectl 2>/dev/null || true)}

[[ -n $KUBECTL_BIN && -x $KUBECTL_BIN ]] || { echo 'Linux kubectl is required' >&2; exit 2; }
[[ ${KUBECTL_BIN,,} != *.exe && $KUBECTL_BIN != /mnt/?/* ]] || { echo 'Use a Linux kubectl binary inside WSL' >&2; exit 2; }
command -v docker >/dev/null 2>&1 || { echo 'docker is required' >&2; exit 2; }

rm -rf -- "$IMAGE_DIR"
mkdir -p -- "$IMAGE_DIR" "$OUT_DIR"
cp -- "$KUBECTL_BIN" "$IMAGE_DIR/kubectl"
cat > "$IMAGE_DIR/Dockerfile" <<'DOCKER'
FROM alpine:3.23
RUN apk add --no-cache bash curl jq openssl coreutils util-linux ncurses git ca-certificates
COPY kubectl /usr/local/bin/kubectl
RUN chmod 755 /usr/local/bin/kubectl && bash --version && kubectl version --client
USER 10001:10001
WORKDIR /data
DOCKER

docker build -t "$IMAGE" "$IMAGE_DIR"
docker image inspect "$IMAGE" --format '{{.Id}}' > "$OUT_DIR/runtime-image-id.txt"

# Optional explicit import into a local validation container/vcluster.
if [[ -n ${SNTL_VALIDATION_CONTAINER:-} ]]; then
    docker save "$IMAGE" | docker exec -i "$SNTL_VALIDATION_CONTAINER" ctr --namespace k8s.io images import -
fi
printf 'Built %s\n' "$IMAGE"
