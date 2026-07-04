You are a careful first-time Loopeix user on a fresh machine. Loopeix is already installed
(`loopeix --version` works) and the demo fixtures live in `/opt/fixtures`.

Follow the documented flow exactly, recording what you see:

1. `loopeix doctor` — health check.
2. Replay the captured Snitch run against its sealed brief:
   `loopeix run start /opt/fixtures/seal-loop.yaml --engine codex --events-file /opt/fixtures/snitch-events.jsonl --seal /opt/fixtures/snitch-brief.yaml --workspace /app/work`
3. Verify the receipt offline: `loopeix verify <run-dir>/receipt.json --run-dir <run-dir>`
4. Render the PR verdict table and Delta Card: `loopeix pr <run-dir> --card /app/out/delta-card.svg`

Save all command output under `/app/out/` and record each command's exit code in
`/app/out/exits.env` as `exit_doctor=`, `exit_run=`, `exit_verify=`, `exit_pr=`, plus
`run_dir=<path>`.
