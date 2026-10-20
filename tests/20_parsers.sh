#!/usr/bin/env bash
# Layer 2 — pure parser unit tests. Sources showctl in SHOW_TEST_MODE (no side effects) and calls the
# sh_* transforms directly, then runs the normalize.py units. Fast, no Docker. Locks in the IPv6 bugs.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.bash"
load_parsers

echo "── sh_hostports: masscan .list → host:port (IPv6 bracketed) ──"
got="$(printf 'open tcp 80 10.0.0.1 1\nopen tcp 443 2001:db8::1 1\n# comment\nopen udp 53 10.0.0.9 1\n' | sh_hostports)"
want="$(printf '10.0.0.1:80\n[2001:db8::1]:443\n10.0.0.9:53')"
assert_eq "sh_hostports: v4 bare, v6 bracketed, ignores non-open lines" "$want" "$got"

echo "── sh_ports: host:port → port (last-colon, IPv6-safe) ──"
got="$(printf '10.0.0.1:80\n[2001:db8::1]:443\nhost.corp:8443\n' | sh_ports)"
assert_eq "sh_ports: v4/v6-bracketed/hostname all yield the trailing port" "$(printf '80\n443\n8443')" "$got"

echo "── sh_urls: host:port → http+https URLs (IPv6 bracketed in URL) ──"
got="$(printf '10.0.0.1:80\n[2001:db8::1]:443\n' | sh_urls)"
want="$(printf 'http://10.0.0.1:80\nhttps://10.0.0.1:80\nhttp://[2001:db8::1]:443\nhttps://[2001:db8::1]:443')"
assert_eq "sh_urls: emits http+https per host:port, keeps v6 brackets" "$want" "$got"
# a row with no numeric port must produce nothing (guards against junk URLs)
got="$(printf 'garbage-no-port\n' | sh_urls)"
assert_eq "sh_urls: drops rows without a numeric port" "" "$got"

echo "── sh_family: alive hosts → v4 (default) | v6 split ──"
alive="$(printf '10.0.0.1\n2001:db8::1\nhost.corp\n')"   # hostname has no ':' → falls to the v4 list
assert_eq "sh_family 4: keeps v4 + hostnames"  "$(printf '10.0.0.1\nhost.corp')" "$(printf '%s\n' "$alive" | sh_family 4)"
assert_eq "sh_family 6: keeps v6 only"         "2001:db8::1"                      "$(printf '%s\n' "$alive" | sh_family 6)"
assert_eq "sh_family default is v4"            "$(printf '10.0.0.1\nhost.corp')" "$(printf '%s\n' "$alive" | sh_family)"

echo "── latest_run: newest NON-EMPTY dir by name (skip the empty startup dir; ignore mtime) ──"
d="$(mktemp -d)"
mkdir -p "$d/out/20260101T000000Z" "$d/out/20260707T120000Z" "$d/out/20260709T000000Z"
: > "$d/out/20260101T000000Z/masscan.list"    # populated (oldest)
: > "$d/out/20260707T120000Z/masscan.list"    # populated (middle) ← expected winner
touch "$d/out/20260101T000000Z/masscan.list"  # touch oldest LAST → an mtime sort would wrongly return it
# 20260709T000000Z stays EMPTY (newest name) → must be SKIPPED like the fresh startup dir
got="$( SHOW_HOME="$d"; OUTROOT="./out"; latest_run )"
assert_eq "latest_run picks newest NON-EMPTY (skips empty newest, ignores mtime)" "$d/out/20260707T120000Z/" "$got"
rm -rf "$d"

echo "── manifest: status reflects tool failures (degraded) + normalize failure ──"
if have jq; then
  mfn(){ # DEGRADED_TOOLS  NORMALIZE_OK  → "status<TAB>degraded_tools" of a generated manifest
    local mt; mt="$(mktemp -d)"; : > "$mt/hosts.ndjson"
    ( OUT="$mt"; SCAN_ID="2026-01-01T00:00:00Z"; START_EPOCH=0; NORMALIZE_OK="$2"; DEGRADED_TOOLS="$1"
      manifest daily >/dev/null 2>&1 )
    jq -rc '[.status, (.degraded_tools|tostring)] | @tsv' "$mt/run_manifest.json"; rm -rf "$mt"
  }
  # capture BEFORE the tab-IFS read — a `IFS=$'\t' read <<<"$(mfn …)"` would leak the tab IFS into the
  # command substitution and mis-split DEGRADED_TOOLS inside manifest.
  out="$(mfn "masscan httpx" 1)"; IFS=$'\t' read -r st dt <<<"$out"
  assert_eq "manifest status=degraded when a tool failed"    "degraded"           "$st"
  assert_eq "manifest degraded_tools lists the failures"     '["httpx","masscan"]' "$dt"
  out="$(mfn "" 1)"; IFS=$'\t' read -r st _ <<<"$out"
  assert_eq "manifest status=ok when nothing failed"         "ok"                 "$st"
  out="$(mfn "masscan" 0)"; IFS=$'\t' read -r st _ <<<"$out"
  assert_eq "manifest status=normalize_failed dominates"     "normalize_failed"   "$st"
  # a normalize parse-error sidecar (.normalize_degraded) must also degrade the run
  mt="$(mktemp -d)"; : > "$mt/hosts.ndjson"; printf 'httpx\n' > "$mt/.normalize_degraded"
  ( OUT="$mt"; SCAN_ID="2026-01-01T00:00:00Z"; START_EPOCH=0; NORMALIZE_OK=1; DEGRADED_TOOLS="" ; manifest daily >/dev/null 2>&1 )
  assert_eq "manifest degrades on a normalize parse-error sidecar" "degraded"  "$(jq -r '.status' "$mt/run_manifest.json")"
  assert_eq "manifest folds sidecar tools into degraded_tools"     '["httpx"]' "$(jq -rc '.degraded_tools' "$mt/run_manifest.json")"
  rm -rf "$mt"
else
  skip "manifest degraded status" "jq required"
fi

echo "── config_check: accepts the shipped config, rejects invalid enum-ish knobs ──"
if have yq; then
  ckbad(){ # yq-mutation → runs config_check on a mutated copy of show.yaml, echoes its exit status
    local bad; bad="$(mktemp).yaml"; cp "$REPO/show.yaml" "$bad"
    yq -i "$1" "$bad"
    ( CFG="$bad"; config_check >/dev/null 2>&1 ); local rc=$?
    rm -f "$bad"; echo "$rc"
  }
  assert_eq "config_check accepts the shipped show.yaml"   "0" "$( ( CFG="$REPO/show.yaml"; config_check >/dev/null 2>&1 ); echo $? )"
  assert_eq "config_check rejects version_intensity typo"  "1" "$(ckbad '.scan.nmap.version_intensity = "flll"')"
  assert_eq "config_check rejects a nuclei severity typo"  "1" "$(ckbad '.scan.nuclei.severity_daily = "hihg,critical"')"
  assert_eq "config_check rejects a UDP masscan port spec" "1" "$(ckbad '.scan.masscan.ports = "U:53,80"')"
else
  skip "config_check enum validation" "yq required"
fi

echo "── normalize: .normalize_degraded sidecar lifecycle (written on bad input, cleared on clean re-run) ──"
if have python3; then
  d="$(mktemp -d)"
  printf '{bad json}\n' > "$d/httpx.json"
  python3 "$NORMALIZE" --run-dir "$d" --scan-id x --observed-at x >/dev/null 2>&1
  [[ -f "$d/.normalize_degraded" ]] && pass "bad input writes the degraded sidecar" || fail "bad input writes the degraded sidecar"
  printf '{"url":"http://10.0.0.1:80","scheme":"http"}\n' > "$d/httpx.json"   # fix the input
  python3 "$NORMALIZE" --run-dir "$d" --scan-id x --observed-at x >/dev/null 2>&1
  [[ -f "$d/.normalize_degraded" ]] && fail "clean re-run clears the stale sidecar" "sidecar persisted" || pass "clean re-run clears the stale sidecar"
  rm -rf "$d"
else skip "normalize sidecar lifecycle" "python3 absent"; fi

echo "── normalize.py units ──"
if have python3; then
  if python3 "$TESTS_DIR/unit_normalize.py"; then pass "normalize.py units (see ✓ above)"
  else fail "normalize.py units" "one or more normalize.py unit tests failed"; fi
else
  skip "normalize.py units" "python3 absent"
fi

summary "20_parsers"
