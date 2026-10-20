# SHOW test suite

Private test suite for SHOW (the whole `tests/` dir is gitignored). Mirrors STRIP's framework so the two
read alike. Bash-only — `showctl` is bash and we source it for its parser functions; zsh does not populate
`BASH_SOURCE`/arrays the same way. Run everything with `bash`, never `sh`/`zsh`.

## Run

```bash
tests/run.sh                       # layers 1–4 (layer 5 skips unless opted in)
tests/run.sh 20                    # only layer(s) matching '20'
SHOW_INTEGRATION=1 tests/run.sh 50 # opt-in: real containers
```

Exit code is non-zero if any layer fails.

## Layers

| # | File | What it proves | Docker |
|---|------|----------------|--------|
| 1 | `10_static.sh` | `bash -n`, `py_compile`, shellcheck, and grep-guards that lock in every reviewed fix: crun uses `-T </dev/null` and always names a service; nmap `-Pn` + a `-6` pass; nuclei scans `live_urls.txt` (never raw `urls.txt`/`hosts_ports.txt`); URL lists require a host and reject junk (`^https?://…\S*$`); IPv6 host:port is bracketed; `SHOW_TEST_MODE` guards mkdir + dispatch; `latest_run` sorts by name / skips empty dirs / avoids mtime and `merge` drops the empty startup dir first; primary-tool failures (`mark_degraded`) **and** malformed tool output (`read_jsonl` object-rows, corrupt nmap XML, unusable `testssl.json`) surface as `status:"degraded"` + `degraded_tools[]`; `discover`/`merge` exit non-zero on degraded and the `.normalize_degraded` sidecar clears on a clean re-run; `normalize.py` brackets IPv6 in tls `matched_at`, keeps **open** ports only, derives IP via `host_from_httpx`, and normalizes screenshot paths; `config_check` validates every knob (rates, timing, `version_intensity`, nuclei severity tokens, TCP-only port specs); amd64 images are platform-pinned; and no functional `show.yaml` knob (inputs/scan/screenshots/output — `brand` excepted) is dead. | config check only (skips if down) |
| 2 | `20_parsers.sh` | Sources `showctl` in `SHOW_TEST_MODE` and exercises the **real** `sh_*` transforms (`sh_hostports`/`sh_ports`/`sh_urls`/`sh_family`), `latest_run` (name-vs-mtime + empty-dir skip), the manifest degraded/ok/normalize_failed status (incl. the `.normalize_degraded` sidecar fold), `config_check` accept/reject on a mutated `show.yaml`, and the sidecar lifecycle — then runs the `normalize.py` units (`port_from_url`, `cpe22→23`, private-IP, severity/category, `envelope`, `parse_masscan`, `parse_nmap_xml` open-only + corrupt-XML degrade, `read_jsonl` dict enforcement, `matched_at` IPv6, `host_from_httpx`, `shots_map`, `load_testssl` shapes). | no |
| 3 | `30_golden.sh` | `normalize.py` over recorded tool output (`fixtures/`) matches `golden/` byte-for-byte after blanking `scan_id`/`observed_at`; the emitted stream set matches too. | no (host python3) |
| 4 | `40_contracts.sh` | The current container images accept the exact flags `showctl` passes (nmap/httpx/nuclei/testssl incl. a no-URI `--fast` acceptance/gowitness) and the discovery image bundles masscan/arp-scan/nbtscan/python3. Catches upstream image drift. | yes (skips per-tool if image missing) |
| 5 | `50_integration.sh` | Drives `./showctl merge <run-dir>` — the real crun wrapper, merge branch, and scan_id derivation — over recorded tool output, emitting valid NDJSON via the container. Opt-in. | yes (`SHOW_INTEGRATION=1`) |

## Fixtures & golden

`fixtures/<name>/` holds recorded tool output (masscan.list, nmap.xml/nmap6.xml, httpx.json, nuclei.jsonl,
testssl.json, …). `golden/<name>/` holds the expected normalized NDJSON. Cases:

- `basic_v4` — full IPv4 run, all five streams (incl. tls).
- `ipv6_bracket` — IPv6 path: bracketed masscan, `nmap6.xml`, v6 web asset.
- `empty` — nothing alive; every stream is the §2.11 empty-stream sentinel.

After an **intentional** `normalize.py` change, regenerate and review:

```bash
tests/regen_golden.sh
git diff tests/golden      # confirm the delta is what you meant
```

## No drift

Layers 1, 2 and 4 read `showctl` / source its functions / probe the real images rather than re-implementing
its behaviour, so a change to `showctl` that breaks the contract fails a test instead of silently diverging.
