# RHEL-LAB host preflight — private before/after receipts

This standalone shell script captures **read-only, unprivileged** Ubuntu/Linux
host observations. It uses /bin/bash and /usr/bin/python3 (standard library only).
It does **not** install dependencies, run apt, use sudo, connect to a VM, launch
tests, access RHEL services, or probe networks.

## Before any experiment

From a local checkout of this reviewed branch, run:

    bash scripts/host_preflight.sh --phase before --repo "$PWD"

If you do not have a checkout, omit --repo; the host audit still works, but
the repository commit is recorded as not supplied.

The script prints a unique SESSION path, e.g.
~/.local/state/qsol-rhel-lab/host-audits/<random-id>. Copy that path exactly.
The default output parent and each new session are operator-owned/private (0700).
Each JSON receipt and its SHA-256 checksum is created with mode 0600 and
never overwritten. Paths and directories are checked against unsafe ancestors
and symlinks. The script refuses execution as root.

## After the separately authorized experiment

Using the **same script version** and exactly the session path from before:

    bash scripts/host_preflight.sh --phase after --session "$SESSION"
    bash scripts/host_preflight.sh --phase verify --session "$SESSION"

This creates:
- before.json and before.json.sha256
- after.json and after.json.sha256
- comparison.json and comparison.json.sha256

The verify mode recomputes all receipt digests and the before/after comparison.
It does not overwrite evidence. Before and after capture different UTC timestamps,
boot IDs, versions and capacities as observed; volatile free space and available
memory are omitted **only from the comparison list**, not from the raw receipts.

Captured observations include OS/kernel/boot IDs, CPU virtualization flags, RAM,
local disk capacity, UEFI DBX SHA-256 if readable, Secure Boot state, kernel lockdown,
AppArmor/SELinux indicators, /dev/kvm access, QEMU/libvirt tools and relevant
installed package information. Missing tools or denied firmware reads are reported
as unavailable, **not** automatically installed or misrepresented as passes.

## Interpretation and privacy

A receipt SHA-256 detects byte changes only when the digest is retained and
compared against an independent trusted copy; it is **not a signature**. The
same account that owns both receipt and checksum can replace both. Keep an
independent copy or record the digest outside the host for stronger provenance.

These receipts may contain a boot ID, CPU model, software versions and local
configuration details. **Never commit or publish the JSON files**. Inspect
and redact before sharing. Store them outside the repository.

An up-to-date host and a valid receipt are not proof of effective VM isolation.
Actual KVM/libvirt, disk budget, SELinux/sVirt and egress checks require separate
host verification and explicit owner authorization. PR CI exercises mocked and
read-only shell/JSON behavior only; no virtualization.
