#!/usr/bin/env bash
# Layer 4 — tool contract tests. Prove the CURRENT container images actually accept the flags showctl
# passes them (catches upstream image drift). No scans are run — only each tool's help / presence.
# Needs Docker; may pull images on first run. Individual checks skip if an image is unavailable.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.bash"
cd "$REPO"

echo "── tool contracts ──"
if ! docker_ok; then skip "contract tests" "docker not available"; summary "40_contracts"; exit $?; fi

dc(){ docker compose -f docker-compose.show.yml "$@"; }

helptext(){ # service helpargs... -> tool help (stdout+stderr), never fails the caller
  local svc="$1"; shift
  dc run --rm -T "$svc" "$@" </dev/null 2>&1 || true
}
check(){ # service "helpargs" flag...
  local svc="$1" hf="$2"; shift 2
  local out; read -r -a _hf <<<"$hf"; out="$(helptext "$svc" "${_hf[@]}")"
  if [[ -z "$out" ]]; then skip "contract: $svc" "no help output (image unavailable?)"; return; fi
  local f
  for f in "$@"; do
    if grep -qF -- "$f" <<<"$out"; then pass "contract: $svc accepts $f"
    else fail "contract: $svc accepts $f" "flag not found in $svc help output"; fi
  done
}

# discovery bundles three binaries + python3 — assert each exists (a per-binary loop; `command -v` with
# several args only resolves the first under the image's /bin/sh)
out="$(dc run --rm -T discovery sh -c \
  'for b in masscan arp-scan nbtscan python3; do command -v "$b" >/dev/null 2>&1 && echo "have $b" || echo "missing $b"; done' \
  </dev/null 2>&1 || true)"
if ! grep -qE '^(have|missing) ' <<<"$out"; then skip "contract: discovery" "image unavailable"; else
  for bin in masscan arp-scan nbtscan python3; do
    if grep -qx "have $bin" <<<"$out"; then pass "discovery image has $bin"; else fail "discovery image has $bin" "not on PATH"; fi
  done
fi

# nmap — service/version/OS detection, IPv6 pass, XML+greppable output
check nmap    "--help"                -sV -O -Pn -6 --version-all --version-light -iL -oX -oG
# httpx — the probe/detail flags SHOW consumes in the normalizer
check httpx   "-h"                    -json -silent -status-code -title -tech-detect -rl -web-server -content-type -content-length -location -hash
# nuclei — rate/concurrency/severity + JSONL output
check nuclei  "-h"                    -severity -rl -c -jsonl -ni -stats -l -o
# testssl — JSON file output + warnings mode (all in --help)
check testssl "--help"                --warnings --file --jsonfile
# --fast is valid but man-page-only (absent from --help). Prove the image accepts it WITHOUT a network
# scan: `testssl --fast` with no URI parses the flag then errors on the MISSING TARGET — not "unrecognized
# option" the way a bogus flag does. No URI ⇒ no connection is ever attempted.
ftxt="$(helptext testssl --fast)"
if [[ -z "$ftxt" ]]; then skip "contract: testssl accepts --fast" "image unavailable"
elif grep -qiE 'unrecognized option|illegal option|unknown option' <<<"$ftxt"; then
  fail "contract: testssl accepts --fast" "testssl rejected --fast as unrecognized"
else pass "contract: testssl accepts --fast (no-URI acceptance)"; fi
# gowitness — file input + screenshot path + JSONL output
check gowitness "scan file --help"    -f --screenshot-path --write-jsonl --write-jsonl-file --threads

summary "40_contracts"
