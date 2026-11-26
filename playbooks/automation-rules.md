# Automation rules

Status: design only. Deployed by Terraform (`azurerm_sentinel_automation_rule`) in Phase 4.

| ID | Order | Condition | Action | Note |
|---|---|---|---|---|
| AR-001 | 1 | Incident created, any analytics rule DET-xxx | Run PB-001 | Every incident gets the enrichment comment |
| AR-002 | 2 | Incident created, severity High | Run PB-002 | |
| AR-003 | 3 | Incident created by DET-002, DET-003, DET-005 or DET-010 | Run PB-003 (approval first) | Containment never runs without approval |
| AR-900 | 0 | Incident created by DET-009 | Close as Benign Positive with comment "planned teardown" | Created only at the start of Phase 5 (`enable_teardown_rule = true`) for TC-240. Before that, every DET-009 incident stays open |
