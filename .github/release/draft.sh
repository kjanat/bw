#!/usr/bin/env bash
set -euo pipefail

workspace_for() {
	case "${1}" in
		vaultwarden) printf '%s\n' packages/vaultwarden ;;
		cli) printf '%s\n' apps/cli ;;
		*)
			printf 'Unknown package: %s\n' "${1}" >&2
			return 1
			;;
	esac
}

case "${1}" in
	prepare)
		: "${TAG:?}" "${GITHUB_RUN_ID:?}" "${GITHUB_OUTPUT:?}"
		sha=$(git rev-parse HEAD)
		git merge-base --is-ancestor "${sha}" origin/master
		version=${TAG#v}
		packages=(vaultwarden cli)
		for package in "${packages[@]}"; do
			workspace=$(workspace_for "${package}")
			jq -e --arg version "${version}" '.version == $version and .private != true and .publishConfig.access == "public"' "${workspace}/package.json"
		done
		release=$(jq -cn --arg tag "${TAG}" --arg version "${version}" --arg sha "${sha}" \
			--argjson run "${GITHUB_RUN_ID}" --argjson packages '["vaultwarden","cli"]' \
			'{tag:$tag,version:$version,sha:$sha,run:$run,packages:$packages,prerelease:($version | split("+")[0] | contains("-"))}')
		existing=$(gh release list --limit 1000 --json tagName,isDraft | jq -c --arg tag "${TAG}" 'map(select(.tagName == $tag))')
		if [[ "${existing}" == '[]' ]]; then
			args=("${TAG}" --draft --verify-tag --generate-notes --title "${TAG}")
			prerelease=$(jq -r '.prerelease' <<<"${release}")
			if [[ "${prerelease}" == true ]]; then args+=(--prerelease); fi
			gh release create "${args[@]}"
		else
			jq -e 'length == 1 and .[0].isDraft' <<<"${existing}"
		fi
		printf 'release=%s\n' "${release}" >>"${GITHUB_OUTPUT}"
		;;
	attach)
		: "${RELEASE:?}" "${GITHUB_STEP_SUMMARY:?}"
		tag=$(jq -er '.tag' <<<"${RELEASE}")
		sha=$(git rev-parse HEAD)
		expected_sha=$(jq -er '.sha' <<<"${RELEASE}")
		[[ "${sha}" == "${expected_sha}" ]]
		cd artifacts
		sha256sum -c ./*.sha256
		version=$(jq -er '.version' <<<"${RELEASE}")
		archives=()
		for package in $(jq -er '.packages[]' <<<"${RELEASE}"); do
			workspace=$(workspace_for "${package}")
			expected_name=$(jq -er '.name' "../${workspace}/package.json")
			tar -xOf "${package}.tgz" package/package.json \
				| jq -e --arg name "${expected_name}" --arg version "${version}" '.name == $name and .version == $version'
			archives+=("${package}.tgz")
		done
		jq . <<<"${RELEASE}" >release.json
		sha256sum -- "${archives[@]}" release.json >SHA256SUMS
		sha256sum -c SHA256SUMS
		gh release view "${tag}" --json isDraft --jq '.isDraft' | jq -e '. == true'
		gh release upload "${tag}" "${archives[@]}" SHA256SUMS release.json --clobber
		printf 'Draft ready for review: %s\n' "${tag}" >>"${GITHUB_STEP_SUMMARY}"
		;;
	*)
		printf 'Usage: draft.sh prepare|attach\n' >&2
		exit 1
		;;
esac
