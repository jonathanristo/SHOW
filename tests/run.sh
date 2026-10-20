#!/usr/bin/env bash
# SHOW test runner. Layers run in order; pass a substring to run a subset. Layer 5 is opt-in.
#   ./run.sh                      # layers 1–4 (5 skips unless SHOW_INTEGRATION=1)
#   ./run.sh 20                   # only the layer(s) whose name contains '20'
#   SHOW_INTEGRATION=1 ./run.sh 50
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
filter="${1:-}"
layers=(10_static 20_parsers 30_golden 40_contracts 50_integration)

rc=0
for L in "${layers[@]}"; do
  [[ -n "$filter" && "$L" != *"$filter"* ]] && continue
  echo; echo "════════════════ $L ════════════════"
  bash "$HERE/$L.sh" || rc=1
done

echo
if [[ $rc -eq 0 ]]; then echo "════════════════ ALL LAYERS PASSED ════════════════"
else                    echo "════════════════ FAILURES ABOVE — see ✗ lines ════════════════"; fi
exit $rc
