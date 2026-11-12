# RHEL-LAB research roadmap

## RHEL-LAB-001 — repository foundation

- [x] Define AGENTS.md operator/agent boundaries.
- [x] Document lab containment, experiment protocol and security disclosure.
- [x] Supply deterministic, standard-library SHA-256 evidence inventory and verification.
- [x] Supply safe unit tests and CI without guest workloads.
- [ ] Owner review and merge; CI status to be verified separately.

## RHEL-LAB-002 — authorized guest baseline

- [ ] Select exact RHEL release and validate subscription/installation terms.
- [ ] Document actual hypervisor and guest configurations.
- [ ] Record signed-off VM scope, offline networking checks, exact package/kernel baseline.
- [ ] Create reproducible snapshot and artifact receipts.

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
