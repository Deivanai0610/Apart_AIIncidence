#!/usr/bin/env bash
# Run one complete measured block of the frozen CHIMERA schedule in schedule order.
# Requires OPENROUTER_API_KEY in the environment. Paid: every episode calls both models.
# Usage: bash run_block.sh <block-number 1..4>
# Every row is attempted once. Rows whose latest attempt ended as
# infrastructure_failure are then rerun with --rerun-of, at most MAX_RERUNS
# times per row. Every attempt stays in the manifest; nothing is hidden.
set -u
BLOCK="${1:?block number required (1 to 4)}"
MAX_RERUNS="${MAX_RERUNS:-2}"
REPO="${CHIMERA_REPO:-$(cd "$(dirname "$0")/.." && pwd)}"
LOGDIR="${CHIMERA_RUN_LOGS:-$REPO/artifacts/runs/logs}"
SCHEDULE=artifacts/runs/schedules/main.json
mkdir -p "$LOGDIR"
cd "$REPO" || exit 1
export CHIMERA_ALLOW_PAID=1
export OPENROUTER_ATTACKER_MODEL=z-ai/glm-5.3
export OPENROUTER_DEFENDER_MODEL=google/gemini-3.7-flash

run_one() {  # $1 = row id, $2 = optional rerun-of attempt id
  local ID="$1" RERUN="${2:-}" START EXIT SUMMARY ERR LOG
  LOG="$LOGDIR/$ID${RERUN:+.rerun-$(date -u +%H%M%S)}.log"
  START=$(date -u +%H:%M:%SZ)
  if [ -n "$RERUN" ]; then
    .venv/bin/python -m chimera run --live --confirm-paid \
      --schedule "$SCHEDULE" --schedule-episode-id "$ID" --rerun-of "$RERUN" > "$LOG" 2>&1
  else
    .venv/bin/python -m chimera run --live --confirm-paid \
      --schedule "$SCHEDULE" --schedule-episode-id "$ID" > "$LOG" 2>&1
  fi
  EXIT=$?
  SUMMARY=$(grep -E '^\{' "$LOG" | tail -1 | python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
    print(d.get('episode_id'), d.get('termination_reason'), 'calls=' + str(d.get('provider_requests')))
except Exception:
    print('no-metadata')")
  ERR=$(grep -iE 'error' "$LOG" | grep -vE '^\{' | tail -1)
  echo "$START $ID${RERUN:+ (rerun of $RERUN)} exit=$EXIT $SUMMARY ${ERR:+| $ERR}"
}

# Latest attempt id and its termination for one row, from the manifest.
latest_attempt() {  # prints "<attempt_id> <termination_or_status>"
  python3 - "$1" <<'EOF'
import json, sys
row = sys.argv[1]
try:
    rows = [json.loads(l) for l in open("artifacts/runs/measured/manifest.jsonl")]
except FileNotFoundError:
    rows = []
family = [r for r in rows if r["episode_id"] == row or r["episode_id"].startswith(row + "-r")]
if not family:
    print("none none"); sys.exit()
starts = [r["episode_id"] for r in family if r["status"] == "starting"]
latest = starts[-1]
last = [r for r in family if r["episode_id"] == latest][-1]
print(latest, last.get("termination_reason") or last["status"])
EOF
}

IDS=$(python3 - "$BLOCK" <<'EOF'
import json, sys
block = int(sys.argv[1])
rows = json.load(open("artifacts/runs/schedules/main.json"))["rows"]
for r in rows:
    if r["block"] == block:
        print(r["episode_id"])
EOF
)

echo "block $BLOCK: $(echo "$IDS" | wc -l | tr -d ' ') episodes, started $(date -u +%H:%M:%SZ)"
for ID in $IDS; do
  read -r ATTEMPT STATE <<<"$(latest_attempt "$ID")"
  if [ "$ATTEMPT" != "none" ]; then
    echo "skip $ID: already attempted ($ATTEMPT -> $STATE)"
    continue
  fi
  run_one "$ID"
done

for PASS in $(seq 1 "$MAX_RERUNS"); do
  RERAN=0
  for ID in $IDS; do
    read -r ATTEMPT STATE <<<"$(latest_attempt "$ID")"
    if [ "$STATE" = "infrastructure_failure" ] || [ "$STATE" = "starting" ] || [ "$STATE" = "running" ]; then
      echo "rerun pass $PASS: $ID after $ATTEMPT"
      run_one "$ID" "$ATTEMPT"
      RERAN=1
      # A rerun that fails before any provider call is systemic (range, budget,
      # lease). Stop the block instead of burning more claims.
      LASTLOG=$(ls -t "$LOGDIR/$ID".rerun-*.log | head -1)
      if grep -E '^\{' "$LASTLOG" | tail -1 | grep -q '"provider_requests":0,"run_kind":"measured","termination_reason":"infrastructure_failure"'; then
        echo "STOP: rerun of $ID failed before any provider call; systemic problem, not retrying"
        exit 2
      fi
    fi
  done
  [ "$RERAN" = 0 ] && break
done

echo "block $BLOCK finished $(date -u +%H:%M:%SZ)"
python3 - "$BLOCK" <<'EOF'
import json, sys
from collections import Counter
block = int(sys.argv[1])
rows = [json.loads(l) for l in open("artifacts/runs/measured/manifest.jsonl")]
term = [r for r in rows if r["block"] == block and r["status"] in ("terminal", "infrastructure_failure")]
print("block", block, "terminal reasons (all attempts):", dict(Counter(r.get("termination_reason") for r in term)))
sched = [r["episode_id"] for r in json.load(open("artifacts/runs/schedules/main.json"))["rows"] if r["block"] == block]
unresolved = []
for row in sched:
    fam = [r for r in rows if r["episode_id"] == row or r["episode_id"].startswith(row + "-r")]
    starts = [r["episode_id"] for r in fam if r["status"] == "starting"]
    if not starts:
        unresolved.append((row, "not attempted")); continue
    last = [r for r in fam if r["episode_id"] == starts[-1]][-1]
    if last["status"] not in ("terminal", "infrastructure_failure") or last.get("termination_reason") == "infrastructure_failure":
        unresolved.append((row, last.get("termination_reason") or last["status"]))
print("unresolved rows:", unresolved if unresolved else "none")
sys.exit(2 if unresolved else 0)
EOF
