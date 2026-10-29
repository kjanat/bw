#!/usr/bin/env bash
set -euo pipefail
: "${PACKAGE:?}" "${RELEASE:?}" "${RUNNER_TEMP:?}"
cd artifacts
checksum=$(awk -v file="${PACKAGE}.tgz" '$2 == file { print }' SHA256SUMS)
[[ -n "${checksum}" ]]
printf '%s\n' "${checksum}" | sha256sum -c -
version=$(jq -er '.version' <<<"${RELEASE}")
workspace=packages/vaultwarden
if [[ "${PACKAGE}" == cli ]]; then workspace=apps/cli; fi
name=$(jq -er '.name' "../${workspace}/package.json")
tar -xOf "${PACKAGE}.tgz" package/package.json \
	| jq -e --arg name "${name}" --arg version "${version}" '.name == $name and .version == $version'
archive_integrity="sha512-$(openssl dgst -sha512 -binary "${PACKAGE}.tgz" | openssl base64 -A)"
if published=$(npm --prefix "${RUNNER_TEMP}" view "${name}@${version}" dist.integrity --json --registry https://registry.npmjs.org); then
	published_integrity=$(jq -er '[.] | flatten | select(length == 1) | .[0] | strings' <<<"${published}")
	[[ "${published_integrity}" == "${archive_integrity}" ]]
	printf 'Already published identical tarball: %s@%s\n' "${name}" "${version}"
else
	jq -e '.error.code == "E404"' <<<"${published}"
	dist_tag=latest
	if [[ "${version}" == *-* ]]; then dist_tag=next; fi
	npm --prefix "${RUNNER_TEMP}" publish "$(realpath "./${PACKAGE}.tgz")" --access public --provenance --ignore-scripts --tag "${dist_tag}"
fi
