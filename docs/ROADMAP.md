# RHEL-LAB research roadmap

## RHEL-LAB-001 — repository foundation

- [x] Define AGENTS.md operator/agent boundaries.
- [x] Document lab containment, experiment protocol and security disclosure.
- [x] Supply deterministic, standard-library SHA-256 evidence inventory and verification.
- [x] Supply safe unit tests and CI without guest workloads.
- [x] Owner reviewed and merged RHEL-LAB-001; CI verified green on the merge commit.

## RHEL-LAB-002 — The Virtual Testbed

- [x] Provide a strictly offline-only x86_64 KVM profile and serial-console-only libvirt domain XML.
- [x] Add no-write plan, approved disk preparation, persistent/live XML inspection and guarded offline snapshot commands.
- [x] Add a baseline receipt template, documented containment checklist, regression tests and Daybreak scan gate.
- [ ] Owner review, CI validation and security audit of this PR.
- [ ] Select/download exact RHEL ISO under valid entitlement and verify media integrity.
- [ ] Confirm actual host KVM/libvirt capability and security settings; record authorized VM scope.
- [ ] Manually define/install the isolated guest after authorization; verify *actual* network and host isolation.
- [ ] Capture a real clean baseline snapshot with exact guest/kernel/package evidence.

Source tooling completion is not equivalent to guest installation, execution, isolation proof or a completed Daybreak scan.

## RHEL-LAB-003 — bounded reliability campaign

- [ ] Define non-destructive baseline workload and independent expected results.
- [ ] Run operator-approved guest-only kernel self-tests and concurrency tests.
- [ ] Store complete raw evidence securely, including negative results.
- [ ] Reproduce from clean snapshots, pin input and tool versions.

## RHEL-LAB-004 — targeted analysis and disclosure

- [ ] Perform scoped fuzzing only with containment and run approval.
- [ ] Triage crashes versus memory/resource exhaustion, environment artifacts and true defects.
- [ ] Independently reproduce security-relevant findings.
- [ ] Report privately to the vendor and coordinate disclosure.

The roadmap does not assert that any RHEL test, security scan, or vulnerability discovery has already occurred.
