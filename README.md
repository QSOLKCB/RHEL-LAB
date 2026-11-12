# QSOL-IMC RHEL-LAB

**Reproducible Red Hat Enterprise Linux reliability and security research.**

RHEL-LAB is an Apache-2.0-licensed research workspace for controlled experiments on RHEL installations in isolated virtual machines running on owned or explicitly authorized hardware. The project prioritizes exact provenance, independently repeatable results, and responsible disclosure.

> Status: RHEL-LAB-002 virtual-testbed tooling proposed for review. No RHEL VM has been installed, tested or booted by this repository.

## No GitHub Pages / web deployment

**Security policy:** no GitHub Pages site, hosted dashboard or public endpoint. GitHub's server-managed Pages workflow ran after the previous merge even though this repository contains no Pages deployment YAML. The current Pages site must be removed administratively, not by deleting our source-check workflow. See [Pages shutdown and prevention](docs/PAGES_SHUTDOWN.md). The separate CI guard reports a security-policy failure until GitHub's repository metadata explicitly shows Pages disabled.

## Research boundaries

- Run experiments only on owned or explicitly authorized lab systems. No Red Hat-hosted services, third-party targets, or production infrastructure.
- Treat a developer subscription as product access, **not** authorization to probe Red Hat infrastructure.
- Do not run kernel fuzzers, elevated stress tests, exploit demonstrations, or external scans in GitHub Actions.
- Keep guest VM disk images, crash dumps, tokens, personally identifiable information, and unpublished security findings out of public commits.
- Report potentially security-sensitive findings privately through the vendor's designated security channel; follow coordinated disclosure.

See [AGENTS.md](AGENTS.md), [SECURITY.md](SECURITY.md), and [docs/RESEARCH_PROTOCOL.md](docs/RESEARCH_PROTOCOL.md) before performing experiments.

## Repository map

| Path | Purpose |
| --- | --- |
| AGENTS.md | Binding instructions for automated contributors |
| docs/LAB_SETUP.md | Isolation and local lab prerequisites |
| docs/RESEARCH_PROTOCOL.md | Experiment gates, provenance, disclosure |
| docs/ROADMAP.md | Phased milestones and acceptance criteria |
| scripts/evidence.py | Dependency-free SHA-256 evidence inventory and verifier |
| scripts/testbed.py | Operator-gated local KVM profile, auditing and offline disk snapshots |
| tests/ | Safe standard-library unit tests |
| .github/workflows/ci.yml | Non-privileged source checks and no-Pages status policy |
| scripts/pages_policy.py | Fail-closed offline check of GitHub's Pages metadata and committed workflow contents |

## Quick start

Requires Python 3.11 or newer. No third-party Python packages are needed. The commands below test the evidence tooling; **they do not install RHEL or execute security tests**.

    uv run --no-project python -m unittest discover -s tests -v

Alternatively:

    python3 -m unittest discover -s tests -v

To inventory an evidence directory, write the manifest **outside** the evidence directory:

    uv run --no-project python scripts/evidence.py seal --input ./local/capture-001 --output ./local/capture-001.manifest.json
    uv run --no-project python scripts/evidence.py verify --input ./local/capture-001 --manifest ./local/capture-001.manifest.json

The example requires the capture directory to exist. The manifest is deterministic (no generated timestamp), records relative paths, byte sizes and SHA-256 digests, rejects symlinks, and will not overwrite an existing manifest. Its output directory must be operator-owned and private (0700); it writes the manifest as 0600 using pinned directory descriptors. Seal only a quiescent or externally snapshotted evidence tree: per-file race checks cannot guarantee a global point-in-time view. For provenance, separately record target/kernel/package versions, test configuration, seed, exact source SHA, time, tool versions, and whether the test actually executed. A manifest establishes byte identity, not scientific validity.

## Virtual testbed (RHEL-LAB-002)

The optional KVM/QEMU testbed is **offline-first, local-only, and operator-gated**. It uses an unprivileged libvirt user connection, a VM profile with no virtual NIC, serial-console-only installation, and private disk/snapshot state outside the repository. It has no Pages deployment or public endpoint.

- [Virtual Testbed guide](docs/VIRTUAL_TESTBED.md) — plan, manual preparation, definition/audit, offline snapshots, limitations.
- [Daybreak security gate](docs/DAYBREAK_GATE.md) — source scanning and fixes come **before** any authorized live experimentation.
- [Lab profile](lab/testbed.json) and [baseline receipt template](templates/baseline_receipt.json).

Once a local, authorized installer ISO is available, inspect the zero-write plan with:

    uv run --no-project python scripts/testbed.py plan --lab-root "$HOME/rhel-lab-state" --iso "$HOME/Downloads/RHEL-INSTALLER.iso"

This command only produces an XML/JSON plan and performs no host mutation. Host-changing commands require separate explicit approval; no actual guest, security scan or isolated network proof has been performed.

## Research priorities

1. Establish isolated, disposable RHEL guests and capture exact environment baselines.
2. Establish reproducible baseline reliability tests, with explicit operator approval.
3. Investigate bounded concurrency, stress, and kernel self-test campaigns.
4. Conduct targeted fuzzing only after the scope and containment gates pass.
5. Independently reproduce findings, preserve negative results, and disclose security issues privately before public discussion.

## Licence and attribution

Copyright 2026 QSOL-IMC contributors. Licensed under the [Apache License, Version 2.0](LICENSE).

RHEL and Red Hat are trademarks of Red Hat, Inc. This is independent research; no endorsement, vendor authorization for off-lab testing, or affiliation is implied.
