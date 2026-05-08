#!/usr/bin/env bash
set -euo pipefail

if ! command -v docker >/dev/null 2>&1; then
  echo "docker is required" >&2
  exit 1
fi

IMAGE_REPO="${1:-${IMAGE_REPO:-}}"
if [[ -z "${IMAGE_REPO}" ]]; then
  echo "Usage: $0 <image-repo>  # ex: ghcr.io/acme/oblivious-node" >&2
  exit 1
fi

TAG="${TAG:-$(git rev-parse --short=12 HEAD 2>/dev/null || date +%Y%m%d%H%M%S)}"
PLATFORM="${PLATFORM:-linux/amd64}"
DOCKERFILE="${DOCKERFILE:-deploy/Dockerfile.oblivious_node}"
OUTPUT_ENV_FILE="${OUTPUT_ENV_FILE:-deploy/phala/image-ref.env}"

IMAGE_TAG_REF="${IMAGE_REPO}:${TAG}"

echo "Building and pushing ${IMAGE_TAG_REF} for ${PLATFORM}..."
docker buildx build \
  --platform "${PLATFORM}" \
  -f "${DOCKERFILE}" \
  -t "${IMAGE_TAG_REF}" \
  --push \
  .

DIGEST="$(docker buildx imagetools inspect "${IMAGE_TAG_REF}" | awk '/Digest: sha256:/{print $2; exit}')"
if [[ -z "${DIGEST}" ]]; then
  echo "Failed to resolve digest for ${IMAGE_TAG_REF}" >&2
  exit 1
fi

IMAGE_DIGEST_REF="${IMAGE_REPO}@${DIGEST}"
echo "Resolved immutable image ref: ${IMAGE_DIGEST_REF}"

cat > "${OUTPUT_ENV_FILE}" <<EOF
OBLIVIOUS_NODE_IMAGE=${IMAGE_DIGEST_REF}
EOF

echo "Wrote ${OUTPUT_ENV_FILE}"
