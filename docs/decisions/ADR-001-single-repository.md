# ADR-001 One repository for controls and detection

Status: accepted, 2026-11-26.

## Context

A Sentinel detection and response lab was designed first as a separate repository (not published). The GRC controls lab needs detections as evidence for its detective controls, the same Terraform core (workspace, Sentinel, diagnostics, budget) and the same CI and leak checks.

## Decision

Keep one repository, `banking-grc-controls-lab`. The detection rules, playbook designs and Terraform of the Sentinel design become a module of it. Each rule sheet names the controls it evidences (`controls:`), and CTL-011 measures detection coverage of the banking scenarios.

## Consequences

- One tenant, one subscription, one trial clock, one teardown.
- The story for a reader is one chain, from regulation to detection, instead of two half-chains.
- Detection tests keep their TC-2xx range; control tests use TC-3xx.
- The standalone Sentinel repository is not created.
