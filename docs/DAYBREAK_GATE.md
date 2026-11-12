# Daybreak Defense Factory — staged security gate

**Status: TWO SOURCE AUDITS COMPLETED, FINDINGS UNDER REMEDIATION.** Daybreak scanned RHEL-LAB at commit `889248b59e4e2cb7c06d8a635c0a07cb2cd39c1e` in runs `wfr_2ef0982c13d785cbdfbf9ecc157a3ccc863cb4085e09dcd70e9124f86bae68f2` and `wfr_f166c5a69c210c6a14bdb64c37311e11fffd8e8dd8a0e0e5e0bd0e0dfb0cac99`. Eight repository-source findings (three medium, five low) are being addressed. Neither a completed audit nor a green CI workflow proves a live RHEL guest is safe; **no RHEL experiments have been executed**.

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
