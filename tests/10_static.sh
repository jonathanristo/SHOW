#!/usr/bin/env bash
# Layer 1 — static analysis: syntax, lint, and grep-guards that lock in the bugs we chased.
# Fast, no Docker (compose config is skipped when Docker is down).
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.bash"

echo "── syntax & lint ──"
assert_ok "showctl parses (bash -n)"            bash -n "$SHOWCTL"
if have python3; then assert_ok "normalize.py compiles" python3 -m py_compile "$NORMALIZE"
else skip "normalize.py compiles" "python3 absent"; fi
if have shellcheck; then assert_ok "shellcheck clean (-S warning)" shellcheck -S warning "$SHOWCTL"
else skip "shellcheck" "not installed"; fi

echo "── regression guards ──"
ctl="$(cat "$SHOWCTL")"

# crun must pass -T (no TTY) and feed </dev/null so a tool reading stdin can't hang the run
assert_contains "crun disables TTY (-T) and closes stdin" "$ctl" 'compose run -T --rm "$@" </dev/null'

# every crun call names a service — 'crun <flag>' or 'crun<word>' would run masscan against compose itself.
# ([^ (] excludes the `crun(){ … }` definition; `crun +-` catches a flag before the service name.)
if grep -nE 'crun[^ (]|crun +-' "$SHOWCTL" >/dev/null; then
  fail "crun always names a service first" "found 'crun' not followed by a service token"
else pass "crun always names a service first"; fi

# nmap: -Pn (masscan already proved the ports) and a dedicated -6 pass for IPv6
assert_contains "nmap uses -Pn (skip host discovery)" "$ctl" 'nmap -sV -O -Pn'
assert_contains "nmap has an IPv6 (-6) pass"          "$ctl" 'nmap -6 -sV -O -Pn'

# nuclei must scan the httpx-VALIDATED live list (live_urls.txt), never the raw http+https cross-product
# (urls.txt) or the unprobed host:port sweep (hosts_ports.txt) — the exact regression we fixed.
nuclei_cmd="$(grep -A2 'crun nuclei' "$SHOWCTL")"
assert_contains "nuclei -l points at live_urls.txt" "$nuclei_cmd" 'live_urls.txt'
if grep -qE 'hosts_ports\.txt|/urls\.txt' <<<"$nuclei_cmd"; then
  fail "nuclei not pointed at a raw target list" "raw urls.txt / hosts_ports.txt would hit dead schemes/ports"
else pass "nuclei not pointed at a raw target list (urls.txt / hosts_ports.txt)"; fi

# latest_run must sort run dirs by NAME, not mtime; and `merge` must drop the empty startup dir BEFORE
# consulting latest_run — else `showctl merge` normalizes the empty dir it just created this invocation.
lrbody="$(awk '/^latest_run\(\)\{/{f=1} f{print} f&&/^}/{exit}' "$SHOWCTL")"
assert_contains "latest_run sorts run dirs by name (sort -r)" "$lrbody" 'sort -r'
assert_contains "latest_run skips empty dirs (ls -A)"        "$lrbody" 'ls -A'
if grep -qF 'ls -dt' "$SHOWCTL"; then fail "latest_run avoids mtime (no ls -dt)" "mtime sort can select the empty startup dir"
else pass "latest_run avoids mtime (no ls -dt)"; fi
rmln="$(grep -n 'rmdir "$OUT"' "$SHOWCTL" | head -1 | cut -d: -f1)"
lrln="$(grep -n '\$(latest_run)' "$SHOWCTL" | head -1 | cut -d: -f1)"
if [[ -n "$rmln" && -n "$lrln" && "$rmln" -lt "$lrln" ]]; then pass "merge drops empty startup dir before selecting latest"
else fail "merge drops empty startup dir before selecting latest" "rmdir(\$OUT) line $rmln vs latest_run line $lrln"; fi

echo "── degraded-run + input hygiene guards ──"
# primary tool failures must be recorded (mark_degraded), never silently swallowed by || true
for t in masscan nmap httpx nuclei testssl gowitness; do
  assert_contains "primary tool '$t' failure is recorded (mark_degraded)" "$ctl" "mark_degraded $t"
done
# manifest must surface degraded status + the tool list; merge must fail when normalize fails
assert_contains "manifest emits status=degraded on tool failure" "$ctl" 'status="degraded"'
assert_contains "manifest records degraded_tools"                "$ctl" 'degraded_tools:$degraded_tools'
assert_contains "standalone merge fails when normalize fails"    "$ctl" 'merge FAILED: normalization'
assert_contains "standalone discover exits nonzero on degraded"  "$ctl" 'discover: degraded'
# standalone discover runs the same preflight as daily/weekly (config_check + ensure_discovery_image)
disc_body="$(awk '/^  discover\)/{f=1} f{print} f&&/^    ;;/{exit}' "$SHOWCTL")"
assert_contains "discover preflights config_check"           "$disc_body" 'config_check || exit 1'
assert_contains "discover preflights ensure_discovery_image" "$disc_body" 'ensure_discovery_image'
# shots() must guard its jq|sort (like webscan/tls) so malformed httpx.json can't abort the shell under pipefail
shots_body="$(awk '/^shots\(\)\{/{f=1} f{print} f&&/^}/{exit}' "$SHOWCTL")"
assert_contains "shots() guards jq|sort against malformed JSON" "$shots_body" 'shot_urls.txt" || : > '
# normalize.py surfaces malformed tool JSON (parse errors → degraded sidecar the manifest folds in)
nbody="$(cat "$NORMALIZE")"
assert_contains "normalize records parse errors (PARSE_ERRORS)"  "$nbody" 'PARSE_ERRORS.add'
# read_jsonl must enforce dict rows (valid JSON but array/string row → degrade, not an AttributeError crash)
assert_contains "read_jsonl enforces object rows"               "$nbody" 'isinstance(obj, dict)'
assert_contains "normalize writes the degraded sidecar"         "$nbody" '.normalize_degraded'
assert_contains "manifest folds the normalize degraded sidecar" "$ctl"   '.normalize_degraded'
# parse_nmap_xml keeps open ports only (closed/filtered must not reach services/open_ports)
assert_contains "parse_nmap_xml skips non-open states" "$nbody" 'if state != "open"'
# corrupt nmap XML must degrade the run (not read as a clean empty result)
assert_contains "corrupt nmap XML degrades the run"    "$nbody" 'PARSE_ERRORS.add(fn.split'
# the degraded sidecar must be cleared at normalize start so a clean re-run isn't perpetually degraded
assert_contains "normalize clears stale degraded sidecar at start" "$nbody" 'os.remove(sidecar)'
# gowitness screenshot paths must be normalized (no screenshots/screenshots/… or absolute-path leak)
assert_contains "shots_map normalizes screenshot path (basename)"  "$nbody" 'os.path.basename(f)'
# httpx .host may carry a :port — the ip field must be derived safely (never carry a port)
assert_contains "web_assets ip derived via host_from_httpx"        "$nbody" 'ip = host_from_httpx(h)'
# a valid-JSON but unrecognized testssl shape must degrade, not silently empty
assert_contains "unrecognized testssl shape degrades the run"      "$nbody" 'not a recognized testssl shape'
# a recognized list must degrade if ANY row isn't a testssl record (incl. one junk row in a good array)
assert_contains "testssl degrades on any non-record row"           "$nbody" 'any(not (isinstance(e, dict) and "id" in e)'
# URL lists must use a strict, ANCHORED scheme regex: not startswith("http") (lets httpx://bad pass) and
# not an unanchored prefix (lets "https://x:443 junk" pass). Require ^https?://\S+$ on all three.
if grep -q 'startswith("http")' "$SHOWCTL"; then fail "url extraction uses strict scheme regex" "startswith(\"http\") still present"
else pass "url extraction avoids loose startswith(\"http\")"; fi
n="$(grep -Fc '[^/[:space:]]\\S*$")' "$SHOWCTL")"
[[ "$n" -ge 3 ]] && pass "URL filters anchored + host-checked (reject http:/// and trailing junk)" || fail "URL filters anchored+host-checked" "expected ≥3, found $n"
# tls must derive HTTPS from the URL scheme (URL-only rows may omit .scheme), not gate on .scheme
tls_body="$(awk '/^tls\(\)\{/{f=1} f{print} f&&/^}/{exit}' "$SHOWCTL")"
assert_contains "tls derives HTTPS from the URL (^https://)" "$tls_body" 'test("^https://[^/[:space:]]\\S*$")'
if grep -q 'scheme=="https"' <<<"$tls_body"; then fail "tls no longer gates on .scheme" ".scheme==https still required — URL-only HTTPS rows would be skipped"
else pass "tls no longer gates on .scheme (URL-only rows work)"; fi
# standalone merge must surface a normalizer-degraded run (it writes no manifest) via exit code
assert_contains "standalone merge fails on a degraded normalize" "$ctl" 'merge: degraded'
# normalize.py must bracket IPv6 in the tls matched_at (2001:db8::1:443 is ambiguous)
assert_contains "normalize brackets IPv6 in tls matched_at" "$(cat "$NORMALIZE")" 'f"[{ip}]:{port}"'
# config_check must validate the user-tunable knobs (not just a subset)
cfg_body="$(awk '/^config_check\(\)\{/{f=1} f{print} f&&/^}/{exit}' "$SHOWCTL")"
for k in .scan.httpx.rate_limit .scan.nuclei.concurrency .scan.nuclei.rate_limit .scan.nuclei.severity_weekly .scan.masscan.ports .screenshots.gowitness.workers; do
  assert_contains "config_check validates $k" "$cfg_body" "$k"
done
assert_contains "config_check validates nmap version_intensity (enum)" "$cfg_body" 'version_intensity must be full|light'
assert_contains "config_check validates nuclei severity tokens"        "$cfg_body" 'invalid severity'
assert_contains "config_check rejects UDP port specs (TCP-only chain)"  "$cfg_body" 'TCP-only'

# IPv6: masscan host:port output must bracket v6 so the last-colon port split is unambiguous
assert_contains "sh_hostports brackets IPv6 host:port" "$ctl" 'if(ip ~ /:/) print "["ip"]:"$3'

# test hooks: SHOW_TEST_MODE must guard BOTH the run-dir mkdir and the CLI dispatch
assert_contains "SHOW_TEST_MODE guards run-dir mkdir" "$ctl" '"${SHOW_TEST_MODE:-0}" == "1" ]] || mkdir -p "$OUT"'
assert_contains "SHOW_TEST_MODE guards CLI dispatch"  "$ctl" '[[ "${SHOW_TEST_MODE:-0}" != "1" ]]; then'

echo "── no dead config (every functional show.yaml knob is referenced) ──"
if have yq && have jq; then
  # Walk ALL scalar leaves (inputs.* / scan.* / screenshots.* / output.*). `brand` is display-only
  # metadata the pipeline never consumes — the one documented exception.
  while IFS= read -r leaf; do
    [[ -n "$leaf" ]] || continue
    key="${leaf##*.}"                                   # last path segment
    if grep -qF "$leaf" "$SHOWCTL" || grep -qF ".$key" "$SHOWCTL"; then
      pass "config used: $leaf"
    else
      fail "config unused: $leaf" "knob in show.yaml but never read by showctl"
    fi
  done < <(yq -o=json "$REPO/show.yaml" | jq -r 'paths(scalars) | join(".")' \
             | grep -vxE 'brand' )
else
  skip "no-dead-config" "yq/jq not installed"
fi

echo "── compose ──"
if docker_ok; then assert_ok "docker compose config valid" docker compose -f "$REPO/docker-compose.show.yml" config -q
else skip "docker compose config" "docker unavailable"; fi

# amd64-only images must be platform-pinned so they don't warn / mismatch on arm64 (the STRIP-class fix)
cmp="$REPO/docker-compose.show.yml"
for svc in testssl gowitness; do
  blk="$(awk -v s="  $svc:" '$0==s{f=1;next} /^  [a-z]/{f=0} f' "$cmp")"
  if grep -qE 'platform:[[:space:]]*linux/amd64' <<<"$blk"; then pass "compose pins $svc to linux/amd64"
  else fail "compose pins $svc to linux/amd64" "amd64-only image needs a platform pin"; fi
done

summary "10_static"
