# Regulatory scope and applicability

## Lab bank

A fictitious group with a **Swiss bank** (head office, FINMA-supervised) and a **Luxembourg credit institution** (subsidiary, CSSF-supervised, in scope of DORA), serving clients in Switzerland and the EU. This footprint is common and forces the question every such group faces: which rule binds which entity.

## Which instrument applies to which entity

| Instrument | Swiss bank | Luxembourg subsidiary | Note |
|---|---|---|---|
| DORA and its RTS/ITS | Not directly | **Yes** | Swiss banks meet DORA through EU subsidiaries, EU clients' contracts and as ICT providers to EU entities; not as a direct obligation |
| NIS2 | No | Not for the banking activity | DORA is the sector-specific act (NIS2 Art. 4). Kept as cross-reference only |
| AI Act | Only if placing AI systems on the EU market or if outputs are used in the EU | **Yes** (as deployer or provider) | Annex III high-risk obligations apply from 2027-12-02 after the 2026 Digital Omnibus (TO VERIFY) |
| GDPR | When the GDPR territorial scope applies (EU clients) | **Yes** | |
| EBA guidelines | No | Through CSSF circulars and supervision | Status of EBA/GL/2019/04 after DORA TO VERIFY |
| CSSF circulars | No | **Yes** | 20/750 and 22/806 now apply with reduced scope for DORA entities; 25/882 for ICT third parties (CSSF communique 2025, updated 2026-08-27) |
| FINMA Circular 2023/1, 2018/3, guidance | **Yes** | No | FINMA 2023/1 in force since 2024-01-01 |
| Banking Act Art. 47 | **Yes** | No | Luxembourg equivalent: financial sector law Art. 41 |
| FADP and DPO | **Yes** | When Swiss data subjects or Swiss processing are involved | |

A control mapped to both CH and EU requirements is one control with two justifications, not two controls. The dashboard counts it in each jurisdiction.

## Out of scope

Prudential rules (CRR, Basel capital for operational risk), payment services (PSD2, PSD3 and its regulation), MiCA, anti-money-laundering (AMLA, the EU AML package, Swiss AMLA), market abuse, conduct rules (FinSA, MiFID II). They matter to a bank but do not drive the ICT and identity controls this lab tests.

## Verification protocol

Every reference in `requirements/` was written at design time from knowledge of the texts and, for a few items, from secondary sources (CSSF communiques, law firm notes). **None has yet been checked line by line against the official text.** Before any public claim:

1. Open the official source in the file's `source_url` (EUR-Lex, CSSF, FINMA, Fedlex).
2. For each entry: confirm the reference points to the paraphrased content; correct the reference or the topic if not; adjust `confidence`.
3. Set `verified_on` (UTC date) on the file. Record corrections in the CHANGELOG.
4. Re-run `python tools/build_report.py`; the matrix drops the TO VERIFY mention for that file.

Priority order: `low` confidence entries first (REQ-RMF-05, REQ-RMF-06, REQ-CH-05, REQ-LU-06), then FINMA Circular 2023/1 margin numbers, then the incident reporting clocks in `incident-response/reporting-clocks.md`.

## Points known to be in motion (November 2026)

| Topic | What changed or may change | Effect on the lab |
|---|---|---|
| AI Act | Regulation (EU) 2026/1744 (Digital Omnibus on AI, OJ 2026-07-24) postponed Annex III high-risk obligations to 2027-12-02 and Annex I to 2028-08-02, and revised Art. 4 (secondary sources) | Dates in REQ-AIA-02; to confirm on EUR-Lex |
| CSSF | Circular 26/915 (2026-08) brings third-country branches into DORA scope and amends 20/750, 22/806, 25/881 to 25/883 | Branch case not modelled |
| EBA | Alignment of ICT guidelines with DORA | REQ-EBA-01 status |
| Switzerland | Federal approach to AI regulation; reporting duty under the Information Security Act | REQ-CH-06, REQ-CH-08 |
