# Daybreak Defense Factory — staged security gate

**Status: NOT RUN.** RHEL-LAB-002 code should be reviewed through an ordinary GitHub PR and the non-privileged Python CI tests *before* requesting a Daybreak repository scan. Daybreak has not been authorized to run a scan by this milestone.

## Controlled progression

1. Review all changes, particularly the local command boundaries, operator approval tokens, XML allowlist, disk paths, and snapshot race limitations.
2. Check CI for the exact PR head SHA. Unit tests prove only the Python utilities' tested behaviors, not RHEL kernel behavior.
3. Request a **repository source-code security scan** through Daybreak when the owner approves it; use the connected QSOLKCB/RHEL-LAB repository and inspect findings.
4. Fix validated source-code findings on a new feature branch, reproduce reported problems, add regression tests and repeat CI/reviews. No automatic merging.
5. Approve and merge only after review gates pass.
6. Separately prepare/verify a local KVM guest, isolation, permitted licensing, disk capacity and offline access. The owner explicitly authorizes any actual host operation.
7. Only after those gates approve guest startup, local reliability experiments or other active testing. No Red Hat service/third-party probing.

**Important distinction:** Daybreak scans repository source code. It is not a substitute for inspecting real guest firewall rules, proving isolation, running kernel fuzzing or observing a live RHEL VM. No GitHub Actions job may start a guest or conduct privileged/security testing.

## Evidence to retain

- Exact base/head/merge SHA and PR review records
- Python CI run ID, completion state, test outcomes and logs
- Daybreak scan run ID and actual findings once requested/executed
- Individual fixes, test reproductions, negative results and owner approvals
- Separately stored private VM evidence, logs, release/kernel package identities, snapshot hashes and disclosure records

Do not claim "Daybreak clean" until the exact scan has completed successfully for the exact commit and its findings have been reviewed. Unfinished scans or zero results from a failed run are inconclusive.
