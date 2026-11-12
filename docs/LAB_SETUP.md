# Local RHEL lab setup — design checklist

This document specifies containment prerequisites. It is not an installation script and no hardware or guest has been provisioned by this repository.

## Operator prerequisites

- Valid entitlement to run the selected RHEL guest; verify the current Red Hat developer-subscription terms for the intended use.
- Host and hypervisor controlled by the operator; separate dedicated, disposable guest storage.
- RHEL installation media obtained through the vendor's authorized distribution channels.
- An explicit written scope record per campaign: target identifier, owner, test purpose, limits, permitted tools, duration and rollback plan.

## Containment gate

1. Prefer a guest-only/isolated network; no host bridge to a LAN or public-facing interface.
2. Inspect and document actual forwarding, NAT, firewall and DNS behavior; block egress during offline experiments.
3. Do not attach host directories with credentials or sensitive data; disable unneeded shared clipboard, device passthrough and host mounts.
4. Record the VM CPU, RAM, disk, architecture, firmware, virtual NIC, guest snapshot ID and baseline image digest.
5. Confirm a rollback snapshot and disk-space budget before any state-changing test.
6. Avoid making a public repository of crash dumps or core files.
7. If updates require networking, treat that as a separately approved acquisition phase; disconnect before controlled experimental runs.

## Baseline receipt (template fields)

- Research ID; operator; exact test scope and authorization reference
- UTC collection time; repository commit SHA; script revision; RHEL release
- Kernel build; relevant package versions; hypervisor name/version
- VM image digest and snapshot ID; virtual hardware configuration
- Network containment verification and approved exceptions
- Command, arguments, bounded workload, seed, start/end, exit status
- Raw evidence paths, hashes, observed outcome, failures, limitations

**Do not mark this checklist complete until the actual environment and controls have been independently verified.**
