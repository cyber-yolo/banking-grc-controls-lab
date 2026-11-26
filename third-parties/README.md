# ICT third parties

`register-of-information.csv` is a **reduced** register of information for the lab. It shows the logic of DORA Art. 28(3), CSSF Circular 25/882 and FINMA Circular 2018/3 (inventory of outsourced services), not the official templates of Implementing Regulation (EU) 2024/2956 (TO VERIFY), which have many more fields and a fixed reporting format.

CTL-014 checks the file in CI. Mandatory columns: every column except `subcontractors_known` notes and `exit_plan_ref` (mandatory only when `supports_critical_function` is `yes`).

GitHub (TP-004) does not support a critical function and holds no client data: it is listed because the control framework itself depends on it.
