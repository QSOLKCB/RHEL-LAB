# Daybreak Defense Factory — staged security gate

**Status (2026-11-18): NOT CLEARED FOR LIVE RHEL EXPERIMENTS.** The newest completed Daybreak repository scan (`wfr_5b1b1f7872aa10f7c5d709ab538289569c0d0e69a28b6f947794a90fd054f33e`) targeted the then-current main `347aa5748318172e8dbf265e9c2874fc14029936` and reported 13 observations. The remediation branch combines the later QCOW2/storage work with fixes for the remaining findings. A green CI run is not proof of host isolation; the final merged head still requires a fresh scan.

## Reconciled observations

- `acf_2e6e3a40f0a8fc363ee8f78eee67566f`: evidence-tree traversal could consume resources before limiting file count or hashing. Draft PR #17 applies the saved bounded-work fix. Merged PR #14 concerned **manifest decoding**, a different boundary.
- Before this remediation, the Pages status check ran candidate-controlled code. The independent check must continue to execute a trusted-base validator, not scripts checked out from the PR.
- Pull-request code must not execute on a network-capable hosted runner. The remediation workflow limits PR handling to trusted-base policy code inspecting candidate workflows as inert data; Python tests run after merge or by explicit dispatch.
- `acf_3358dca947560d3c7aa45a5db7845a61`: prior PATH-helper issue already has pinned trusted helpers; PR #13 was closed without merging as obsolete. Do not reapply that fix.
- The audit additionally found a blocking unprotected main branch, ISO and snapshot storage-budget gaps, QCOW2 external-file/header inspection gaps, unbounded subprocess capture, unsafe ambient libvirt state, and provenance/host-preflight trust gaps. Source fixes do not replace the administrator-owned branch ruleset gate.

## Mandatory gates before any RHEL guest runs

1. Administrator establishes a main ruleset requiring PRs, review from an eligible **non-author**, all Python matrix checks, an **independent** Pages policy gate, no force-push/deletion, and restricted bypass. Verify the ruleset from GitHub; an inaccessible branch-protection endpoint is not proof of protection.
2. Finish review of draft hardening PRs and check the exact PR head SHA and all CI job results. Never merge just to make an older scan appear clean.
3. Complete bounded ISO staging, disk quotas/free-space checks, snapshot limits and child-output limits. Validate QCOW2 header before `qemu-img info` can follow external file references, then reject external data files, unexpected backing, encryption/snapshots and wrong virtual size.
4. Verify the actual dedicated Linux host, ownership, KVM/libvirt/QEMU versions, SELinux/sVirt profile, filesystem capacity, guest device configuration and **effective egress isolation** independently. A no-NIC domain XML is not enough.
5. Execute the host-only, non-boot Tiny Core canary described in `docs/CLEAN_ROOM_CANARY.md`, under separate explicit owner approval. A boot canary needs a separately hashed serial-console-ready image and fresh approval.
6. Complete a new Daybreak scan of **exact final merged HEAD**; triage all findings, including documented false positives, and sign off only observed evidence.

## Record and classify evidence

Retain exact commits, PR approvals, CI run/job IDs, tool and media identities, test inputs and seeds, UTC dates, exit statuses and negative results. Label evidence **mocked**, **unit-tested**, **statically reviewed**, **Daybreak reported**, **host verified**, or **VM executed** accurately. No privileged VM activity, host stress, external scanning, RHEL installation or media downloads are authorized by this document.

Read AGENTS.md, SECURITY.md, docs/RESEARCH_PROTOCOL.md and docs/VIRTUAL_TESTBED.md before requesting any active operation.
