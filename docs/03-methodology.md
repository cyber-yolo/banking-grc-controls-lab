# Methodology

## What a control is here

A control is a **measure with an owner** that reduces a named risk and meets one or more requirements. A setting alone is not a control; a setting plus an owner, a frequency, evidence and a test is.

Each sheet in `controls/sheets/` states: objective, type (preventive, detective, corrective, directive), automation level, frequency, owner role (first line), reviewer role (second line, EBA/GL/2021/05 three lines of defence), risks, requirements, implementation, evidence items, assertions, two tests, related detections and limits.

## Evidence quality

An evidence item is accepted when it is:

| Criterion | How the lab meets it |
|---|---|
| Relevant | It answers the assertion, nothing broader (one item per question) |
| Complete | Collected with paging; the envelope records the query; sample size stated |
| Accurate | Taken from the system of record by API, not retyped |
| Timely | `collected_at` in the envelope; assertions state their window (7 or 30 days) |
| Authentic | SHA-256 in `manifest.json`, repository commit recorded, archive in a versioned store |
| Reproducible | Same collector and evaluator version give the same result on the same run |

`NO_EVIDENCE` is a result, not a failure to hide: it says the question could not be answered.

## Statuses

Assertion: `PASS`, `FAIL`, `NO_EVIDENCE`. Control: `EFFECTIVE` (design and effectiveness assertions PASS), `DESIGN_ONLY`, `PARTIAL`, `NOT_EFFECTIVE`, `NOT_ASSESSED`, `MANUAL`.

## Where judgement stays human

| Decision | Why it is not automated | Where it is recorded |
|---|---|---|
| Does this reference say what the mapping claims? | Legal interpretation | `requirements/` `verified_on`, CHANGELOG |
| Is the evidence sufficient? | Depends on risk and context | Run sheet, reviewer sign-off |
| Is a gap acceptable? | Risk appetite and accountability | `risk/acceptances/RA-xxx.md` |
| Is the incident major, reportable, to whom? | Classification thresholds and legal consequence | Classification worksheet |
| Is the threshold (99 % MFA, 70 % secure score) right? | Bank-specific | Control sheet `limits` |

## Lab honesty rules

1. A lab with three users over 30 days cannot show what a bank shows over a year. Every sample is stated with its size and period.
2. One person plays first line, second line and management body. Sheets say so.
3. A control proven on the previous tenant (sister repo) is not evidence for the new one.
4. Thresholds are lab choices, labelled as such.
