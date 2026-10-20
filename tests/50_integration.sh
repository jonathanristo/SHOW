#!/usr/bin/env bash
# Layer 5 — integration (opt-in: SHOW_INTEGRATION=1). Drives the REAL production path end-to-end:
# `./showctl merge <run-dir>` exercises the crun wrapper (crun discovery python3 /scripts/normalize.py),
# the merge dispatch branch, scan_id derivation from the run-dir timestamp, and the /scripts mount —
# against recorded tool output. (30_golden runs the normalizer on the host; this proves the container path.)
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.bash"
cd "$REPO"

echo "── integration (opt-in) ──"
if [[ "${SHOW_INTEGRATION:-0}" != "1" ]]; then skip "integration" "set SHOW_INTEGRATION=1 to run"; summary "50_integration"; exit $?; fi
if ! docker_ok; then skip "integration" "docker not available"; summary "50_integration"; exit $?; fi

# a prior run dir with a valid TS name, populated with recorded tool output — the input to `showctl merge`
ts="20260101T000000Z"; rel="data/out/$ts"; run="$REPO/$rel"
rm -rf "$run"; mkdir -p "$run"
cleanup(){ rm -rf "$run" "${run2:-}"; rmdir "$REPO/data/out" 2>/dev/null || true; }
trap cleanup EXIT
cp -R "$TESTS_DIR/fixtures/basic_v4/." "$run/"

# drive the real dispatcher — crun wrapper + normalize + merge, scan_id derived from the run-dir name
if SHOW_AUTHORIZED_BY="ci/integration" ./showctl merge "$run" >/dev/null 2>&1; then
  pass "showctl merge ran the real crun + merge branch"
else
  fail "showctl merge ran the real crun + merge branch" "dispatcher exited non-zero"
fi

# basic_v4 has masscan/nmap/httpx/nuclei/testssl output → all five streams should materialise as valid JSON
for s in web_assets services hosts tls findings; do
  f="$run/$s.ndjson"
  if [[ -s "$f" ]] && jq -e . "$f" >/dev/null 2>&1; then pass "merge emitted valid $s.ndjson"
  else fail "merge emitted valid $s.ndjson" "missing or invalid: $rel/$s.ndjson"; fi
done

# scan_id must be derived from the run-dir timestamp (idempotent re-merge), not merge-time "now"
sid="$(jq -r '.scan_id' "$run/services.ndjson" 2>/dev/null | head -1)"
assert_eq "merge derives scan_id from the run-dir name" "2026-01-01T00:00:00Z" "$sid"

# a corrupt tool artifact must make `showctl merge` exit non-zero (degraded), not report a clean re-merge
run2="$REPO/data/out/20260102T000000Z"; rm -rf "$run2"; mkdir -p "$run2"
cp -R "$TESTS_DIR/fixtures/basic_v4/." "$run2/"
printf '<nmaprun><host><ports><port ' > "$run2/nmap.xml"   # truncate the XML
if SHOW_AUTHORIZED_BY="ci/integration" ./showctl merge "$run2" >/dev/null 2>&1; then
  fail "merge exits non-zero on a corrupt nmap.xml (degraded)" "merge returned 0"
else
  pass "merge exits non-zero on a corrupt nmap.xml (degraded)"
fi
[[ -f "$run2/.normalize_degraded" ]] && pass "merge leaves the degraded sidecar for inspection" || fail "merge leaves the degraded sidecar" "no .normalize_degraded"
rm -rf "$run2"

summary "50_integration"
