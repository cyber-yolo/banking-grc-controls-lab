# Reporting clocks

Which notification clocks may start for a security incident in a bank of the lab's footprint (Swiss head office, Luxembourg subsidiary, EU clients). Used in CTL-012 and tabletop TT-001.

**Every time limit below is TO VERIFY on the official text before use.** They are written from the design-time understanding and secondary sources; this file is exactly what the second-line review in TC-323 must check line by line.

| Regime | Who reports, to whom | Trigger | Clocks (TO VERIFY) | Reference |
|---|---|---|---|---|
| DORA (LU entity) | Financial entity to the CSSF | ICT-related incident classified as **major** | Initial notification within 4 hours of classification and no later than 24 hours after becoming aware; intermediate report within 72 hours of the initial notification; final report within one month of the latest intermediate report | DORA Art. 19; Delegated Regulation (EU) 2025/301 and Implementing Regulation (EU) 2025/302 (numbers TO VERIFY) |
| DORA voluntary | Financial entity to the CSSF | Significant cyber threat | Voluntary | DORA Art. 19(2) (TO VERIFY) |
| FINMA (CH entity) | Bank to FINMA | Cyber attack on critical assets, per FINMA Guidance 05/2020 | First assessment within 24 hours; full report within 72 hours | FINMASA Art. 29(2); FINMA Guidance 05/2020 (current version TO VERIFY) |
| Swiss Information Security Act (CH entity) | Operator of critical infrastructure to the National Cyber Security Centre (BACS) | Cyber attack meeting the reporting criteria | Within 24 hours of discovery | Information Security Act, reporting duty in force since 2025-04-01 (applicability to banks and interplay with the FINMA report TO VERIFY) |
| GDPR (LU entity) | Controller to the CNPD | Personal data breach likely to result in a risk | Without undue delay, where feasible within 72 hours | GDPR Art. 33 |
| GDPR data subjects | Controller to clients | High risk to their rights | Without undue delay | GDPR Art. 34 |
| FADP (CH entity) | Controller to the FDPIC | Breach likely to cause a high risk | As soon as possible | FADP Art. 24 |

## Notes

- Several clocks can run in parallel for one incident. The worksheet records each one separately; one report never stands for another unless the official text says so.
- NIS2 reporting does not apply to banks covered by DORA (NIS2 Art. 4, see `requirements/eu-nis2.yaml`).
- The lab never sends a report. Tabletop outputs are drafts marked EXERCISE.
