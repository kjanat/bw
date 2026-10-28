# Releasing vw

## Build, tests and previews

CI runs formatting, source checks and package builds independently. Type checks,
lint and unit tests use the checkout, with Turbo building their workspace
dependencies. The package build uses `bun pm pack --ignore-scripts` and uploads
the archives and SHA-256 sidecars as workflow artifacts. Separate consumers
install the exact archives under Node 24.8.0, Node 26 and Bun on Linux amd64,
plus Node 26 on Linux arm64. Each consumer checks package versions, independent
PBKDF2 and Argon2id vectors, authenticated encryption, all four KDBX worker
fixtures, and SDK prelogin/login/sync through a local HTTP fixture. The full
Vaultwarden server matrix runs on Node 26 alongside this workflow, with each
server's pinned Bitwarden CLI reference.

The `pkg-pr-new` workflow starts when CI begins. It waits for the build-ready
artifact, publishes the prebuilt archives, then runs the package consumers against
the preview archives. The preview hashes must match the original CI artifacts.

## Prepare a draft

Update both package versions and merge the change. Create and push a version tag
whose version matches `packages/vaultwarden/package.json` and
`apps/cli/package.json`:

```sh
git verify-commit <release-commit>
git tag -s v0.1.0 <release-commit> -m 'v0.1.0'
git push origin v0.1.0
```

A `v*` tag starts Release. To prepare or retry an existing tag manually:

```sh
gh workflow run release.yml -f tag=v0.1.0
```

Release creates a GitHub draft if none exists, builds and tests the tagged
commit, then attaches the tested `vaultwarden.tgz` and `cli.tgz` archives,
`SHA256SUMS`, and `release.json`. The workflow does not publish the draft or
publish packages to npm.

## Approve and publish

Review the draft notes, checks and archives, then publish the GitHub release.
The `release.published` event validates the release metadata, waits for the
successful Release workflow, compares each attached archive byte-for-byte with
the tested build artifact, then publishes that archive to npm with provenance
and lifecycle scripts disabled. Prerelease versions use the `next` dist-tag.

Configure npm trusted publishing for both packages after they exist on npm:

```sh
for package in vaultwarden vaultwarden-cli; do
  npm trust github "@kjanat/${package}" --repo kjanat/vw --file publish.yml --environment npm --allow-stage-publish --allow-publish
done
```

The `npm` environment may also provide `NPM_TOKEN` as an authentication
fallback.
