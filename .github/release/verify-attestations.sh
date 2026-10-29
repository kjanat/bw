#!/usr/bin/env bash
set -euo pipefail
: "${TAG:?}" "${GH_REPO:?}"
sha=$(git rev-parse HEAD)
for asset in vaultwarden.tgz cli.tgz SHA256SUMS release.json; do
	gh attestation verify "artifacts/${asset}" \
		--repo "${GH_REPO}" \
		--signer-workflow "${GH_REPO}/.github/workflows/release.yml" \
		--source-ref "refs/tags/${TAG}" \
		--source-digest "${sha}" \
		--deny-self-hosted-runners
done
