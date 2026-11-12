# RHEL-LAB-002 — The Virtual Testbed

This milestone supplies an offline-first *host-side implementation*, not a preinstalled RHEL guest. No VM, kernel experiment, Red Hat service or Daybreak scan is executed in GitHub Actions. The testbed runs only on an operator-owned Linux host, after explicit approval.

## Design constraints

- KVM/QEMU under the least-privileged user libvirt connection: qemu:///session. No sudo or system-wide daemon required by these scripts.
- One x86_64 guest, 2 vCPUs, 4096 MiB RAM, standalone 48 GiB QCOW2 virtual disk. Configuration is in lab/testbed.json.
- **No guest NIC, bridge, NAT, hostdev, host share, USB redirection, graphics listener or public service** in the generated domain XML.
- Serial PTY console only. Guest ISO must be obtained separately from authorized Red Hat distribution; no proprietary image is committed.
- Images, private receipts and XML live in a pinned, operator-owned 0700 directory under trusted ancestors **outside the Git repository**.
- Every host-changing command is explicit, opt-in, and fail-closed. No automatic boot, package installation, VM definition, snapshot restore, or host network configuration.
- A definition/active XML audit rejects unexpected disks, device passthrough, guest networking and external graphics. **This is a configuration audit, not proof of effective egress isolation.**
- No GitHub Pages, public dashboard or network endpoint.

## Prepare the host manually

Use a personally controlled Linux host with KVM support and local libvirt/QEMU tools installed by the operator according to their OS instructions. You need virsh, qemu-img, a working per-user qemu:///session connection, access to /dev/kvm and sufficient disk space. Do not install packages automatically as part of CI or this project.

Check the actual hardware, hypervisor, firmware support, host ownership, VM resource budget, filesystem permissions and guest media authenticity yourself. The lab-root parent and ancestors must be root/operator-owned and not group/other writable (the root-owned sticky /tmp convention is recognized); a new lab root is created 0700. Avoid shared mountpoints. The scripted plan **does not** check that a physical host is isolated.

Download the correct RHEL installer ISO using your own authorized account, verify its official checksum/signature, and keep it outside Git. No vendor access credential belongs in a script, PR or public log.

## Commands (host only, not GitHub Actions)

From the checked-out repository, set paths before any mutating action:

    LAB="$HOME/rhel-lab-state"
    ISO="$HOME/Downloads/RHEL-INSTALLER.iso"

Preview the generated domain XML and paths without execution. The ISO must actually exist:

    uv run --no-project python scripts/testbed.py plan --lab-root "$LAB" --iso "$ISO"

After manually reviewing the XML and approving disk preparation, run:

    uv run --no-project python scripts/testbed.py prepare \
      --lab-root "$LAB" --iso "$ISO" \
      --approve I_AUTHORIZE_LOCAL_VM_PREPARATION

This creates the private folder, a blank QCOW2 image and domain.xml only. It **does not** define, start, install or connect a guest. The exact approval phrase is deliberate.

Inspect domain.xml and then, **only after explicit owner authorization for this VM**, manually define and boot it with the user libvirt connection:

    virsh -c qemu:///session define "$LAB/domain.xml"
    virsh -c qemu:///session start rhel-lab-offline-01
    virsh -c qemu:///session console rhel-lab-offline-01

The console is serial-only; the selected RHEL installer must support or be configured for serial/text installation (for example, console=ttyS0 and inst.text via the ISO's own boot configuration). If your ISO does not support that boot path, stop and make a reviewed change rather than adding a public graphics listener or a network adapter.

Audit both persistent and current domain XML (including possible live changes):

    uv run --no-project python scripts/testbed.py audit-defined --lab-root "$LAB" --iso "$ISO"

Re-run this after installation, host/libvirt configuration changes and before each experiment. The audit does not prove firewall state, process isolation or that the guest cannot access host services via other channels. A no-NIC VM still needs review of storage, console, device and host controls.

## Offline snapshot and receipt

First shut down the guest cleanly and establish that **no other process is writing its disk**. This step is mandatory. A guest-state check alone cannot prevent a process from starting the VM while copying; coordinate exclusive ownership of the host during conversion.

    virsh -c qemu:///session shutdown rhel-lab-offline-01
    virsh -c qemu:///session domstate rhel-lab-offline-01

Only when it reports shut off and an approved exclusive offline window exists, take a copy of its standalone QCOW2 disk:

    SHA="$(git rev-parse HEAD)"
    uv run --no-project python scripts/testbed.py snapshot \
      --lab-root "$LAB" --iso "$ISO" \
      --label baseline-001 --source-sha "$SHA" \
      --approve I_AUTHORIZE_OFFLINE_SNAPSHOT

The snapshot command:
1. Re-audits the persistent and current libvirt definitions.
2. Checks virsh domstate reports exactly "shut off".
3. Checks for a standalone QCOW2 image, then invokes qemu-img convert (source to new private image).
4. Refuses existing destination/receipt names and uses a no-clobber hard-link for final publication.
5. Records SHA-256, exact source commit, byte count and UTC time in a local receipt.

This is an **offline disk copy**, not a libvirt RAM-state snapshot and not a guaranteed atomic capture against hostile/concurrent writers. The operation now pins trusted directory and file descriptors, pre-creates output with exclusive owner-only permissions and invokes qemu-img through inherited Linux /proc/self/fd handles; `/proc` must be available. A non-cooperating writer with the operator's identity or a live guest can still invalidate a snapshot. Never use qemu-img against a running VM disk.

Verify the resulting evidence directory using scripts/evidence.py, storing its manifest outside the directory being sealed. Preserve guest kernel, release, package versions, original media checksum, VM settings, snapshot identifiers, command line, exit status and negative findings in a separate private baseline receipt.

## What this milestone does not do

The repository does not deploy an RHEL guest automatically, bypass subscription conditions, install a hypervisor, configure the host firewall, prove network egress isolation, take a real snapshot in CI, run kernel tests, or claim vendor acceptance of findings. Owner signoff and independently verified isolation are required before RHEL-LAB-003.

## Test and review gates

    uv run --no-project python -m unittest discover -s tests -v
    uv run --no-project python -m compileall -q scripts tests

The unit tests simulate unsafe profile changes, network injection, path substitution, root/symlink attacks, missing approvals, running guest snapshot refusal and both libvirt XML views. They do not invoke real QEMU/virsh or use a VM.

Read AGENTS.md, docs/RESEARCH_PROTOCOL.md, and docs/DAYBREAK_GATE.md before approving any live operation.
