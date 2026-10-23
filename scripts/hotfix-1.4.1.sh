#!/usr/bin/env bash
# One-time, user-requested consolidation of 1.4.1 through 1.4.4.
set -Eeuo pipefail

: "${GITHUB_REPOSITORY:?}" "${BUILD_COMMIT:?}"
[[ "$GITHUB_REPOSITORY" == SawaMEN/Firewall-UI ]]
[[ "$(tr -d '[:space:]' < VERSION)" == 1.4.1 ]]
[[ "$(git log -1 --format=%s)" == 'hotfix: 1.4.1' ]]
[[ "$(git rev-parse HEAD^)" == 50c78b4db8b8771b8e069085c63dd087c988e14e ]]
[[ "$(git rev-parse HEAD)" == "$BUILD_COMMIT" ]]
[[ "$(gh api "repos/$GITHUB_REPOSITORY/branches/main" --jq '.commit.sha')" == "$BUILD_COMMIT" ]]

tag_target() {
  # GitHub may return a JSON null value for a missing ref. Accept only an
  # actual object SHA; never mistake a missing tag for an unexpected tag.
  local sha
  sha="$(gh api "repos/$GITHUB_REPOSITORY/git/ref/tags/$1" --jq '.object.sha' 2>/dev/null)" || return 0
  [[ "$sha" =~ ^[0-9a-f]{40}$ ]] && printf '%s\n' "$sha"
  return 0
}

case "${1:-}" in
  publish)
    # Prepare and validate every local asset before replacing the old release.
    assets=(dist-stable/firewall-ui-linux-amd64 dist-stable/firewall-ui-linux-arm64
      dist-stable/update.json release-images/stable/firewall-ui-docker-linux-amd64.tar.gz
      release-images/stable/firewall-ui-docker-linux-arm64.tar.gz)
    for asset in "${assets[@]}"; do test -s "$asset"; done
    python3 - <<'PY'
import hashlib, json, os, pathlib
manifest = json.loads(pathlib.Path('dist-stable/update.json').read_text())
assert manifest['version'] == '1.4.1' and manifest['channel'] == 'stable'
assert manifest['commit'] == os.environ['BUILD_COMMIT']
for arch in ('amd64', 'arm64'):
    for key, path in ((arch, pathlib.Path('dist-stable') / f'firewall-ui-linux-{arch}'),
                      (f'docker-{arch}', pathlib.Path('release-images/stable') / f'firewall-ui-docker-linux-{arch}.tar.gz')):
        asset = manifest['assets'][key]
        assert asset['url'] == f"https://github.com/{os.environ['GITHUB_REPOSITORY']}/releases/download/v1.4.1/{path.name}"
        assert asset['sha256'] == hashlib.sha256(path.read_bytes()).hexdigest()
PY
    notes="$(mktemp)"
    trap 'rm -f -- "$notes"' EXIT
    python3 - <<'PY' > "$notes"
import pathlib
text = pathlib.Path('docs/CHANGELOG.md').read_text()
print(text.split('## 1.4.1\n', 1)[1].split('\n## ', 1)[0].strip())
PY
    target="$(tag_target v1.4.1)"
    if [[ "$target" == "$BUILD_COMMIT" ]] && gh release view v1.4.1 >/dev/null 2>&1; then
      # The second upstream completion normally reaches this path. Never
      # replace an already complete release or churn its downloadable assets.
      names="$(gh release view v1.4.1 --json assets --jq '.assets[].name')"
      complete=true
      for asset in "${assets[@]}"; do
        if ! grep -Fxq "${asset##*/}" <<< "$names"; then complete=false; fi
      done
      if [[ "$complete" != true ]]; then gh release upload v1.4.1 "${assets[@]}" --clobber; fi
      gh release edit v1.4.1 --title 'hotfix 1.4.1' --notes-file "$notes" --latest
      exit 0
    fi
    if [[ -n "$target" && "$target" != "$BUILD_COMMIT" && "$target" != eb22b457d29a318b6f399ea1798f59374f35d0ac ]]; then
      echo 'Refusing to replace an unexpected v1.4.1 tag.' >&2
      exit 1
    fi
    if gh release view v1.4.1 >/dev/null 2>&1; then
      [[ "$target" == eb22b457d29a318b6f399ea1798f59374f35d0ac ]]
      gh release delete v1.4.1 --cleanup-tag -y
    elif [[ "$target" == eb22b457d29a318b6f399ea1798f59374f35d0ac ]]; then
      gh api -X DELETE "repos/$GITHUB_REPOSITORY/git/refs/tags/v1.4.1"
    fi
    gh release create v1.4.1 --target "$BUILD_COMMIT" --title 'hotfix 1.4.1' --latest \
      --notes-file "$notes" "${assets[@]}"
    ;;
  retire)
    # Called only after the workflow verifies the published Docker download.
    [[ "$(tag_target v1.4.1)" == "$BUILD_COMMIT" ]]
    tags=(v1.4.2 v1.4.3 v1.4.4)
    expected=(395f27d36efb73415e6b5586ff4ca6209ef5047c 6d25354901e9f775af1735da0b1489d7c062f4a8 5fa13eb10a663b6a0e08a1f182cca97b0a815e1e)
    # Check all leases before deleting any intermediate release.
    for index in "${!tags[@]}"; do
      target="$(tag_target "${tags[$index]}")"
      if [[ -z "$target" ]] && gh release view "${tags[$index]}" >/dev/null 2>&1; then
        echo "Cannot verify the missing tag ${tags[$index]}." >&2; exit 1
      fi
      [[ -z "$target" || "$target" == "${expected[$index]}" ]] || {
        echo "Refusing to retire changed tag ${tags[$index]}." >&2; exit 1;
      }
    done
    for tag in "${tags[@]}"; do
      if gh release view "$tag" >/dev/null 2>&1; then
        gh release delete "$tag" --cleanup-tag -y
      elif [[ -n "$(tag_target "$tag")" ]]; then
        gh api -X DELETE "repos/$GITHUB_REPOSITORY/git/refs/tags/$tag"
      fi
    done
    ;;
  *) echo 'Expected publish or retire.' >&2; exit 2 ;;
esac
