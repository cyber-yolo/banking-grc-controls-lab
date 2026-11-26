# Roadmap

The binding constraint is time: the M365 E5 trial, the Azure free account credit and the Sentinel trial each last about 30 days. Everything that does not need a tenant is done first, and the most valuable of it is the **verification of regulatory references**, which needs no tenant at all.

## Clocks

| Clock | Starts | Length (TO VERIFY) | Effect at the end |
|---|---|---|---|
| M365 E5 trial | Tenant creation | 30 days | Licences disabled, then tenant data deleted after a grace period |
| Azure free account credit | Subscription sign-up | 30 days or credit used up | Resources disabled unless upgraded. **Do not upgrade** |
| Sentinel free trial | Sentinel enabled on the workspace | 31 days | Normal prices apply |

Start the Azure subscription only when the tenant is ready. Day 0 = `terraform apply` (Sentinel onboarding).

## Phases

| Phase | When | Goal | Exit criteria |
|---|---|---|---|
| 0. Offline | Before day 0 | Repo published, CI green, references verified | CI green; `verified_on` set on at least the DORA, RTS and FINMA files; low-confidence entries resolved; calendar set |
| 1. Foundations | Day 0 to 2 | Tenant, subscription, Terraform core, connectors, break-glass accounts | TC-200 PASS; first collector run done (baseline, FAILs expected and kept) |
| 2. Identity and agents | Day 2 to 10 | CTL-001 to CTL-007 | TC-301 to TC-314 run; Conditional Access moved from report-only to enabled after a review of sign-in logs |
| 3. Data protection | Day 5 to 14 | PV-POL-001 rebuilt (sister repo), Windows 11 VM with Endpoint DLP | TC-315 to TC-318 run; sister repo TC-004 to TC-009 run on the same VM |
| 4. Detection | Day 5 to 18 | DET-001 to DET-013 enabled and tested; CTL-010, CTL-011, CTL-013, CTL-015 | TC-201 to TC-226, TC-319 to TC-322, TC-325, TC-326, TC-329, TC-330 run |
| 5. Response and incident readiness | Day 12 to 21 | PB-001 to PB-003; tabletop TT-001 | TC-231 to TC-233, TC-323, TC-324 run |
| 6. Evidence and teardown | Day 21 to 28 | Final collector run, export, destroy | Final run hashed and archived; `terraform destroy` done; tenant-level objects removed; spend checked 0; TC-240 run |
| 7. Write-up | After day 28, offline | Final dashboard, management summary (TC-332), lessons learned, v1.0 | Every status links to a run; RA decisions dated |

## Cut order if late

DET-011 (needs a phone), PB-003, CTL-005 effectiveness (TC-310), CTL-015 effectiveness (TC-330). Never cut Phase 6.

## Versions

| Version | Content |
|---|---|
| 0.1 | This kit: catalogue, evaluator, Terraform validated |
| 0.2 | Phase 0 exit criteria met (references verified) |
| 0.3 | Lab campaign with evidence runs |
| 1.0 | Teardown done, write-up, every status justified |
