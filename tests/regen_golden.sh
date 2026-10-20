#!/usr/bin/env bash
# Regenerate tests/golden/ from tests/fixtures/ using the CURRENT normalize.py. Run this only after an
# INTENTIONAL change to the normalizer, then `git diff tests/golden` to confirm the change is what you meant.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.bash"
have python3 || { echo "python3 required"; exit 1; }
have jq      || { echo "jq required"; exit 1; }
SID="2026-01-01T00:00:00Z"

for fx in "$TESTS_DIR"/fixtures/*/; do
  name="$(basename "$fx")"
  tmp="$(mktemp -d)"; cp -R "$fx." "$tmp/"
  python3 "$NORMALIZE" --run-dir "$tmp" --scan-id "$SID" --observed-at "$SID" >/dev/null
  dest="$TESTS_DIR/golden/$name"; rm -rf "$dest"; mkdir -p "$dest"
  for f in "$tmp"/*.ndjson; do
    [[ -e "$f" ]] || continue
    normalize_ndjson < "$f" > "$dest/$(basename "$f")"
  done
  rm -rf "$tmp"
  echo "regenerated golden/$name ($(ls "$dest"/*.ndjson 2>/dev/null | wc -l | tr -d ' ') streams)"
done
echo "done — review 'git diff tests/golden' before committing."
