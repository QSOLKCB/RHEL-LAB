# RHEL-LAB research protocol

## Four gates

**Gate 0 — Authorization.** Identify the owned/authorized VM or host and permitted exact operations. Vendor evaluations alone do not extend authorization beyond the operator-controlled lab.

**Gate 1 — Containment.** Confirm isolation, budgets, rollback, disk capacity, and no unwanted network egress. Record measured configuration; do not treat intended isolation as verified isolation.

**Gate 2 — Reproducibility.** Pin source SHA and tool versions. Capture guest OS/kernel, package versions, workload definitions, inputs, seeds and UTC times. Preserve complete raw logs, error states, and negative results; hash files with scripts/evidence.py.

**Gate 3 — Independent review.** Repeat the experiment from an explicitly documented clean baseline. Separate observations from conjecture. Do not publish potential unpatched security vulnerabilities or sensitive exploit material before private reporting and coordinated disclosure.

## Evidence classification

- PLANNED — no execution yet.
- SIMULATED — model or mock; no RHEL target exercised.
- EXECUTED — observed in one actual, authorized run.
- REPRODUCED — observed in repeated explicitly documented runs.
- INDEPENDENTLY_REPRODUCED — reproduced by a separately prepared investigator/environment with independent evidence.
- INCONCLUSIVE — setup, controls or observations were insufficient.

Do not upgrade evidence class merely because CI passed. CI tests only source utilities, not RHEL behavior.

## Result record

A report should contain an experiment ID, hypothesis, authorization, exact environment and versions, provenance SHA, command/workload, bounded resource limits, raw logs, expected outcome, observed outcome, failures, limitations, evidence classification, evidence manifest location, and disclosure status. Include failed experiments without filtering to favorable outcomes.

## Confidentiality

Raw kernel crash data can contain secrets or personal information. Use access-controlled local storage and redact carefully. Public publication requires a separate review. Report suspected Red Hat vulnerabilities privately using current official vendor instructions.

## Campaign approval

Every proposed active campaign must be reviewed by the operator. A code contribution or approved PR is not itself approval to run a security experiment.
