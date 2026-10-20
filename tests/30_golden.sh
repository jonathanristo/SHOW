#!/usr/bin/env bash
# Layer 3 — golden fixtures. normalize.py over recorded tool output must match tests/golden byte-for-byte
# (after blanking scan_id/observed_at). Runs on the host python3 (stdlib only). Regenerate intentional
# changes with tests/regen_golden.sh, then review the diff.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.bash"

echo "── golden ──"
if ! have python3 || ! have jq; then skip "golden fixtures" "python3 and jq required"; summary "30_golden"; exit $?; fi
SID="2026-01-01T00:00:00Z"

for fx in "$TESTS_DIR"/fixtures/*/; do
  name="$(basename "$fx")"
  gold="$TESTS_DIR/golden/$name"
  if [[ ! -d "$gold" ]]; then fail "golden/$name baseline exists" "run tests/regen_golden.sh"; continue; fi

  tmp="$(mktemp -d)"; cp -R "$fx." "$tmp/"
  python3 "$NORMALIZE" --run-dir "$tmp" --scan-id "$SID" --observed-at "$SID" >/dev/null 2>&1

  # the set of emitted streams must equal the golden set (catches a missing / extra stream file)
  produced="$(cd "$tmp"  && ls ./*.ndjson 2>/dev/null | sort | paste -sd, -)"
  expected="$(cd "$gold" && ls ./*.ndjson 2>/dev/null | sort | paste -sd, -)"
  assert_eq "$name: emitted stream set matches golden" "$expected" "$produced"

  # each golden stream must match byte-for-byte after blanking volatile envelope fields
  for g in "$gold"/*.ndjson; do
    b="$(basename "$g")"
    if [[ ! -f "$tmp/$b" ]]; then fail "$name/$b produced" "golden has it, normalizer did not emit it"; continue; fi
    if d="$(diff -u "$g" <(normalize_ndjson < "$tmp/$b"))"; then
      pass "$name/$b matches golden"
    else
      fail "$name/$b differs from golden" "$(printf '%s\n' "$d" | head -6)"
    fi
  done
  rm -rf "$tmp"
done

summary "30_golden"
