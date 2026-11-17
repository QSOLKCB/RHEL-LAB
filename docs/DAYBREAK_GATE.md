# Daybreak Defense Factory — staged security gate

**Status (2026-11-18): NOT CLEARED FOR LIVE RHEL EXPERIMENTS.** Six completed Daybreak repository scans were recorded. The newest completed scan (`wfr_bb281a48fdcfd85b076cd03dbb76b1ecd3761596b0b9d050c7bbf7947f6ac311`) targeted `4d4827af3aad0fcd4fafec891dc8e02a8c6d0215`, not the then-current main `dabb6a29304f99e403b6dbb1154983dacde3cc6d` or the new draft PRs. A green CI run is not proof of host isolation.

## Reconciled observations

- `acf_2e6e3a40f0a8fc363ee8f78eee67566f`: evidence-tree traversal could consume resources before limiting file count or hashing. Draft PR #17 applies the saved bounded-work fix. Merged PR #14 concerned **manifest decoding**, a different boundary.
- The Pages status check currently runs candidate-controlled code. A required independent check must execute a trusted-base validator, not scripts checked out from the PR.
- `acf_3358dca947560d3c7aa45a5db7845a61`: prior PATH-helper issue already has pinned trusted helpers; PR #13 was closed without merging as obsolete. Do not reapply that fix.
- The audit additionally found a blocking unprotected main branch, ISO and snapshot storage-budget gaps, QCOW2 external-file/header inspection gaps, unbounded subprocess capture, and FIFO config reads. Draft PR #16 addresses the config boundary only.

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
