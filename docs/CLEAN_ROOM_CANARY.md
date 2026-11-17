# RHEL-LAB — clean-room canary and adversarial acceptance

**Plan only. No virtual machine has been booted or installed by this document.**

## A. Source-only attack tests (permitted in CI)

Use `python -m compileall -q scripts tests` and `python -m unittest discover -s tests -v` on Python 3.11–3.14. Add deterministic, bounded adversarial cases for malformed and truncated JSON, duplicate keys, invalid UTF-8, non-finite numbers, oversized inputs, FIFO/symlink/special files, directory budgets, sparse and growing evidence, crafted XML subtrees, receipt substitution and mocked PATH helper injection. Use recorded seeds, clear time/memory limits, and negative-result assertions. Never run a guest or fuzz the host inside CI.

## B. Tiny Core non-boot instrument canary

**Goal: validate the RHEL-LAB tools, not Tiny Core.** CorePure64/Tiny Core can be a small media artifact for this purpose. No live RHEL media is needed.

1. Owner acquires original media legally and records its source, official checksum/signature when available, SHA-256 and size. Keep the ISO and receipts outside Git.
2. On a separately approved, unprivileged Linux host, verify trusted media location, private lab root, host space headroom and enforce storage limits before copying anything.
3. Run `scripts/testbed.py plan` and inspect the approved serial-only, no-NIC XML. Compare expected config, paths and resource values.
4. Only with distinct explicit owner approval, run `prepare` and `verify-media`. Check staged ISO digest/inode and private receipts. No boot; a manual domain definition, if authorized, must be audited separately.
5. Dispose of the canary state by separately approved procedure, recreate a fresh root, and check deterministic results with new private receipts.

## C. Optional serial-console boot (separate approval)

A stock Tiny Core ISO may not provide a usable serial login. A boot test needs a **separate**, reviewed serial-console-ready remaster (`console=ttyS0,115200`, serial getty), with original and modified SHA-256 recorded. Keep the guest NIC absent; inspect actual host/guest isolation. Never silently modify source media, and never interpret a boot result as RHEL certification.

## D. RHEL gate

RHEL can begin only after exact-HEAD CI/review, enforced branch ruleset, trusted independent Pages gate, ISO/snapshot resource budgets, QCOW2 preflight, host containment verification, successful non-RHEL canary and exact-HEAD Daybreak findings review. Operator grants a new, specific approval for each state-changing host action.

Every claim must distinguish what was **executed**, **mocked**, **inferred** and **not yet attempted**.
