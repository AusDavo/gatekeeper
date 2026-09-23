#!/bin/bash
# Publishes Gatekeeper to the web root on the server.
#
# The checkout lives outside the web root; only the files the page actually
# loads are copied in, so nothing else in the repo (.git, sources, package
# files) is ever served. Everything else in the web root is deleted.
#
# Usage (on the server):  scripts/deploy.sh [web-root]
# Add a file to FILES when the page starts loading it.

set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
DEST="${1:-/srv/docker/caddy/sites/gatekeeper}"

FILES=(
  index.html
  theme-init.js
  icons.css
  style.css
  bundled.js
  fonts/Geist-Variable.woff2
  fonts/GeistMono-Variable.woff2
)

cd "$REPO"
if [[ -z "${SKIP_PULL:-}" ]]; then
  git pull --ff-only origin main
fi

for f in "${FILES[@]}"; do
  [[ -f "$f" ]] || { echo "Missing $f; refusing to deploy." >&2; exit 1; }
done

# index.html must reference the assets it ships with (scripts/hash-assets.js).
# A mismatch means a rebuild was not committed.
for ref in $(grep -o '[A-Za-z0-9_./-]*?h=[0-9a-f]*' index.html); do
  file="${ref%%\?*}"
  want="${ref##*=}"
  have="$(sha256sum "$file" | cut -c1-${#want})"
  if [[ "$have" != "$want" ]]; then
    echo "$file hashes to $have but index.html expects $want; run npm run build and commit." >&2
    exit 1
  fi
done

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
chmod 755 "$STAGE"  # rsync -a copies this onto the web root
cp --parents -p "${FILES[@]}" "$STAGE/"

mkdir -p "$DEST"
# Mirror the staged files: --delay-updates swaps every changed file in at the
# end, and --delete-after then removes anything that isn't in FILES.
rsync -a --delete --delete-after --delay-updates "$STAGE/" "$DEST/"

echo "Gatekeeper $(git rev-parse --short HEAD) deployed to $DEST at $(date)"
