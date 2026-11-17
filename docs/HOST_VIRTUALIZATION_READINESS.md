# RHEL-LAB — Ubuntu host virtualization enablement gate

**Host-specific observations (2026-11-18, pre-installation, before VM testing):**
Ubuntu 26.04.1 LTS, AMD Ryzen 9 5950X, kernel 7.0.0-43-generic;
no "svm" CPU flag, no /dev/kvm, no loaded kvm modules, and no qemu-img
or virsh packages in the verified private host receipt.
These are observations, NOT evidence of a failed RHEL or Tiny Core guest.

This plan does NOT execute package installation, change firmware, enable
networking, start a daemon or boot a guest. Use the owner-authorized local
host only and record each action in the existing private preflight session.

## Gate A — firmware (manual, no scripts)

In the motherboard's UEFI setup, find AMD "SVM Mode" (sometimes AMD-V).
Enable it if disabled; save and reboot. Board-specific menus differ.
Do not change Secure Boot, SEV, IOMMU or networking in this step.

After reboot:

    lscpu | grep -Ei 'Virtualization|Model name|Hypervisor'
    grep -m1 -ow svm /proc/cpuinfo || true
    ls -l /dev/kvm 2>&1
    lsmod | grep -E '^kvm' || true

If svm is still absent, stop. Check exact motherboard/UEFI revision before
attempting kernel module changes. The CPU supports AMD virtualization;
absence of svm usually points to firmware or platform configuration.

If svm is present but /dev/kvm is absent, inspect diagnostics and consider
loading kvm_amd as a separately authorized host-changing action. Do not
assume missing /dev/kvm proves a CPU or firmware defect.

## Gate B — package plan (simulation, no installation)

Only after SVM is available, inspect the proposed dependency set:

    apt-cache policy qemu-system-x86 qemu-utils libvirt-clients \
      libvirt-daemon-driver-qemu libvirt-daemon-system
    apt-get -s install qemu-system-x86 qemu-utils libvirt-clients \
      libvirt-daemon-driver-qemu libvirt-daemon-system

Review the simulated package changes and services before approving actual
installation. Ubuntu 26.04 offers optional virtualization HWE packages;
do not silently switch to HWE, add third-party repos or enable any network.
Installing libvirt-daemon-system can provision system services and/or
default NAT facilities; the RHEL-LAB scripts exclusively use qemu:///session,
but this does not remove or disable any host-wide service automatically.

With separate owner approval, the operator can run the same vetted package
installation through apt. Package installation is outside RHEL-LAB scripts.

## Gate C — post-install verification, no guest start

    command -v qemu-img
    command -v virsh
    qemu-img --version
    virsh --version
    ls -l /dev/kvm
    id -nG

The helper paths must resolve to trusted /usr/bin/qemu-img and
/usr/bin/virsh for scripts/testbed.py. Group membership alone is not a proof
of KVM accessibility; verify effective read/write access to /dev/kvm.
Use a dedicated unprivileged lab account when practical. A later,
separately authorized virsh -c qemu:///session list --all may launch a
per-user daemon; it is NOT part of the read-only preflight.

## Gate D — independent containment and media budgets

Before creating a VM, verify the actual host account, KVM, libvirt session,
AppArmor/SELinux profile, default host networks, storage and reserved capacity.
No-NIC XML validation does not prove egress isolation. The code separately
enforces a 16 GiB ISO cap; 16–64 GiB virtual disk; virtual-size+4 GiB
snapshot ceiling; and at least 8 GiB free-space reserve.

Run the preflight's --phase after only after the planned experiment. Keep
all receipts outside Git and record exact SHA-256 digests independently.
Never test a live RHEL guest until the code and host isolation gates pass.

References: Canonical Ubuntu Server documentation on KVM/libvirt and
Virtualization Hardware Enablement Stack; QEMU QCOW2 file-format spec.
