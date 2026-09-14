#!/usr/bin/env bash
# Run the four benign-only control episodes (protocol section 5): one per
# active defense B-E, no attacker, same frozen configuration and stamp as the
# measured runs. Only D and E make provider calls (defender only).
# Usage (plain terminal, detached):
#   nohup bash scripts/run_controls.sh > artifacts/runs/logs/controls.log 2>&1 &
# Optional: bash scripts/run_controls.sh B C   (subset, in the given order)
set -u
REPO="${CHIMERA_REPO:-$(cd "$(dirname "$0")/.." && pwd)}"
LOGDIR="${CHIMERA_RUN_LOGS:-$REPO/artifacts/runs/logs}"
mkdir -p "$LOGDIR"
cd "$REPO" || exit 1
export CHIMERA_ALLOW_PAID=1
export OPENROUTER_ATTACKER_MODEL=z-ai/glm-5.3
export OPENROUTER_DEFENDER_MODEL=google/gemini-3.7-flash

CONDITIONS=("$@")
[ ${#CONDITIONS[@]} -eq 0 ] && CONDITIONS=(B C D E)
FAILED=0
echo "controls ${CONDITIONS[*]}: started $(date -u +%H:%M:%SZ)"
for COND in "${CONDITIONS[@]}"; do
  START=$(date -u +%H:%M:%SZ)
  LOG="$LOGDIR/control-$COND-$(date -u +%Y%m%dT%H%M%S).log"
  .venv/bin/python -m chimera run --live --confirm-paid --benign-only \
    --condition "$COND" > "$LOG" 2>&1
  EXIT=$?
  SUMMARY=$(grep -E '^\{' "$LOG" | tail -1 | python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
    print(d.get('episode_id'), d.get('termination_reason'), 'calls=' + str(d.get('provider_requests')))
except Exception:
    print('no-metadata')")
  ERR=$(grep -iE 'error' "$LOG" | grep -vE '^\{' | tail -1)
  echo "$START control $COND exit=$EXIT $SUMMARY ${ERR:+| $ERR}"
  if [ "$EXIT" != 0 ] || echo "$SUMMARY" | grep -q infrastructure_failure; then
    FAILED=1
  fi
done
echo "controls finished $(date -u +%H:%M:%SZ)"
exit $FAILED
