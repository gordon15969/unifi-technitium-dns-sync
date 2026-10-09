#!/usr/bin/env bash
# Build a release package, or start a release.
#
#   scripts/release.sh        build dist/ from HEAD for inspection (changes nothing else)
#   scripts/release.sh --tag  tag vX.Y.Z on HEAD and push the tag; the Release
#                             workflow (.github/workflows/release.yml) then builds
#                             the package with this same script and publishes it
#
# Before releasing: bump VERSION in unifi_technitium_sync.py, add a changelog
# entry to README.md, commit, and push. Requires git and python3; the release
# notes use the gh CLI when it is available.
#
# If GitHub Actions is unavailable, publish by hand after a build:
#   gh release create vX.Y.Z dist/*.tar.gz dist/SHA256SUMS \
#     --verify-tag --title vX.Y.Z --notes-file dist/RELEASE_NOTES.md --latest
set -euo pipefail
cd "$(dirname "$0")/.."

tag_release=false
case "${1:-}" in
  "") ;;
  --tag) tag_release=true ;;
  *) echo "usage: $0 [--tag]" >&2; exit 2 ;;
esac

version=$(sed -n 's/^VERSION = "\(.*\)"/\1/p' unifi_technitium_sync.py)
[ -n "$version" ] || { echo "cannot read VERSION from unifi_technitium_sync.py" >&2; exit 1; }
tag="v$version"
name="unifi-technitium-sync-$version"
out="dist"

if ! git diff --quiet || ! git diff --cached --quiet; then
  echo "Working tree has uncommitted changes; commit them first." >&2; exit 1
fi
if [ -n "$(git ls-files --others --exclude-standard)" ]; then
  echo "Untracked files present; commit or remove them first." >&2; exit 1
fi
grep -q "^- \*\*$version\*\*" README.md || { echo "README.md changelog has no entry for $version" >&2; exit 1; }

echo "== tests =="
test_log=$(mktemp)
trap 'rm -f "$test_log"' EXIT
if ! python3 -m unittest discover -s tests >"$test_log" 2>&1; then
  cat "$test_log" >&2
  echo "Tests failed; nothing was tagged or built." >&2
  exit 1
fi
tail -3 "$test_log"

if $tag_release; then
  git fetch -q origin --tags
  [ "$(git rev-parse HEAD)" = "$(git rev-parse '@{upstream}')" ] || { echo "HEAD is not pushed; push first." >&2; exit 1; }
  if git rev-parse -q --verify "refs/tags/$tag" >/dev/null || [ -n "$(git ls-remote --tags origin "refs/tags/$tag")" ]; then
    echo "Tag $tag already exists; bump VERSION for a new release." >&2; exit 1
  fi
  git tag -a "$tag" -m "Release $version"
  git push origin "$tag"
  echo "Pushed $tag. The Release workflow now builds and publishes it:"
  echo "  gh run list --workflow release.yml --limit 1"
  exit 0
fi

echo "== package =="
rm -rf "$out"; mkdir -p "$out"
git archive --format=tar --prefix="$name/" HEAD | gzip -n -9 > "$out/$name.tar.gz"
(cd "$out" && sha256sum "$name.tar.gz" > SHA256SUMS && cat SHA256SUMS)
tar tzf "$out/$name.tar.gz" | sed 's/^/  /'

repo=$(gh repo view --json nameWithOwner -q .nameWithOwner 2>/dev/null || echo "OWNER/REPO")
entry=$(awk -v v="$version" '
  $0 ~ "^- \\*\\*" v "\\*\\*" { on = 1; print; next }
  on && /^- \*\*/ { exit }
  on && /^## / { exit }
  on && NF == 0 { exit }
  on { print }
' README.md)
{
  echo "## What's new"
  echo
  echo "$entry"
  echo
  echo "## Install"
  echo
  echo '```sh'
  echo "gh release download $tag --repo $repo --pattern '*.tar.gz' --pattern SHA256SUMS"
  echo "sha256sum -c SHA256SUMS"
  echo "tar xzf $name.tar.gz && cd $name"
  echo "sudo ./install.sh"
  echo '```'
  echo
  echo "Then follow the README inside the package: edit \`/etc/unifi-technitium-sync/sync.env\`,"
  echo "run the dry-run, and enable the service. Upgrading from an earlier version:"
  echo "rerun \`sudo ./install.sh\` and restart the service; your configuration and state are kept."
  echo "Requires Python 3.9+ on Debian/Ubuntu with systemd; no other packages."
} > "$out/RELEASE_NOTES.md"
echo "Built $out/ from $(git rev-parse --short HEAD) (nothing tagged or uploaded)."
