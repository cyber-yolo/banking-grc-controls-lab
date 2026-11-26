# ADR-002 Shared tenant with the DLP lab rebuild

Status: accepted, 2026-11-26.

## Context

The sister repository's Purview DLP lab must be rebuilt on a new trial tenant (previous tenant deleted). This lab needs Purview DLP (CTL-008, CTL-009) and its alerts in Sentinel (DET-001).

## Decision

Use the same new tenant and the same campaign window for both repositories.

## Consequences

- Native ingestion of Purview DLP alerts into Sentinel through the Defender XDR connector; no cross-tenant set-up.
- One E5 trial clock for both labs: the calendar in `05-roadmap.md` covers both.
- Evidence from each repository stays in its own repository; CTL-009 references the sister repo's tests by ID.
