# Operational scripts

These were written during the measured series on 13 and 14 September 2026 and
are kept for reproducibility. None of them is part of the verified source tree
(`chimera/`, `range/`, `prompts/`, `tests/`, `configs/`), so editing them does
not invalidate a verification stamp.

- `run_block.sh <block>`: runs every unattempted row of one schedule block in
  order, then reruns rows whose latest attempt ended as `infrastructure_failure`
  (at most `MAX_RERUNS`, default 2), stopping if a rerun fails before its first
  provider call. Exit 2 if any row in the block stays unresolved. Paid.
- `run_controls.sh [B C D E]`: runs the four benign-only control episodes
  (protocol section 5) with `chimera run --live --confirm-paid --benign-only`,
  one per active defense, into `artifacts/runs/control/`. No attacker; only
  D and E call a model (the defender). Paid, about $0.005 per D or E run.
- `run_blocks_chained.sh 1 2 3`: runs blocks back to back and stops at the first
  block with an unresolved row. Run it detached from a plain terminal with
  `nohup`; the Claude Code background-task watchdog killed one run on
  13 September despite 31% free memory.
- `openrouter_probe.py`: sends the harness's exact OpenRouter request shape with
  a one-token prompt and prints the raw status and body. Paid, under $0.001.
  Used to find the `max_completion_tokens` routing rejection.
- `relocate_probe.py`: writes route state on the host and reads it back through
  the running range to check that an atomic file replacement is visible to the
  containers. No provider calls; needs the range up.


Logs default to `artifacts/runs/logs/` (git-ignored with the rest of
`artifacts/runs/`).
