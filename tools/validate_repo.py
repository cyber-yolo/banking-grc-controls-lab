#!/usr/bin/env python3
"""Repository checks run by CI and before every commit.

1. Requirements catalogue: schema, unique IDs, every in-scope requirement mapped.
2. Control sheets: complete, consistent with requirements, risks, evidence
   items, detections, test IDs and controls/catalog.csv.
3. Detection catalogue: every rule sheet is complete and consistent with its
   KQL file, its test IDs, its controls and detections/catalog.csv.
4. Scenarios: every referenced risk, control and detection exists.
5. Leak scan: no GUID, Azure resource path, e-mail address or Terraform state
   outside explicit placeholders.

Usage: python tools/validate_repo.py [--root PATH]
Exit code 0 when clean, 1 otherwise.
"""
from __future__ import annotations

import argparse
import csv
import re
import subprocess
import sys
from pathlib import Path

import yaml

REQUIRED_KEYS = {
    "id", "name", "status", "severity", "banking_scenario", "tactics", "techniques",
    "attack", "attack_rationale", "data_sources", "query_file", "query_frequency",
    "query_period", "trigger_threshold", "parameters", "thresholds", "entities",
    "tests", "false_positives", "response", "controls",
}
SEVERITIES = {"Informational", "Low", "Medium", "High"}
STATUSES = {"draft", "written", "validated", "retired"}
# Tactic names as accepted by the Sentinel API
TACTICS = {
    "Reconnaissance", "ResourceDevelopment", "InitialAccess", "Execution", "Persistence",
    "PrivilegeEscalation", "DefenseEvasion", "CredentialAccess", "Discovery",
    "LateralMovement", "Collection", "CommandAndControl", "Exfiltration", "Impact",
}
ENTITY_TYPES = {"Account", "IP", "Host", "URL", "MailMessage", "CloudApplication", "File"}
GLOBAL_TEMPLATE_VARS = {"internal_domain"}
ISO_DURATION = re.compile(r"^P(T\d+[HM]|\d+D)$")
TECHNIQUE = re.compile(r"^T\d{4}$")
SUBTECHNIQUE = re.compile(r"^T\d{4}(\.\d{3})?$")
TEMPLATE_VAR = re.compile(r"\$\{([a-z_]+)\}")
CATALOG_COLUMNS = ["id", "name", "severity", "tactics", "attack", "data_sources",
                   "positive_test", "negative_test", "status"]

# Leak scan
GUID = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")
SUB_PATH = re.compile(r"/subscriptions/[^\s/\"'`<${]{4,}", re.IGNORECASE)
EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b")
ALLOWED_EMAIL_DOMAINS = {"example.com", "example.org", "example.net"}  # plus any *.example (RFC 2606)
ALLOWED_GUIDS: set[str] = {
    "00000003-0000-0000-c000-000000000000",  # Microsoft Graph application ID, public and identical in every tenant
}

CONTROL_KEYS = {
    "id", "name", "domain", "type", "automation", "frequency", "status", "owner_role", "reviewer_role",
    "objective", "risks", "requirements", "implementation", "evidence", "assertions", "tests", "detections", "limits",
}
CONTROL_TYPES = {"preventive", "detective", "corrective", "directive"}
AUTOMATION = {"automated", "semi-automated", "manual"}
CONFIDENCE = {"high", "medium", "low"}
LAB_SCOPE = {"in", "partial", "out"}
CONTROL_CATALOG_COLUMNS = ["id", "name", "domain", "type", "automation", "frequency", "requirements",
                           "design_test", "effectiveness_test", "status"]
FORBIDDEN_FILES = ("*.tfstate", "*.tfstate.*", "terraform.tfvars", "*.tfplan", "tfplan")
SKIP_DIRS = {".git", ".terraform", ".venv", "node_modules", "evidence"}
TEXT_SUFFIXES = {".md", ".yaml", ".yml", ".kql", ".tf", ".csv", ".json", ".py", ".ps1", ".txt", ".example", ".hcl"}


def iter_files(root: Path):
    """Files git would commit (tracked plus untracked, not ignored).

    Falls back to a plain walk when git is not available.
    """
    try:
        out = subprocess.run(
            ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
            cwd=root, capture_output=True, check=True,
        ).stdout.decode("utf-8")
        for name in filter(None, out.split("\0")):
            path = root / name
            if path.is_file():
                yield path
        return
    except (OSError, subprocess.CalledProcessError):
        pass
    for path in root.rglob("*"):
        if any(part in SKIP_DIRS for part in path.relative_to(root).parts):
            continue
        if path.is_file():
            yield path


def check_rules(root: Path, errors: list[str]) -> None:
    rules_dir = root / "detections" / "rules"
    sheets = sorted(rules_dir.glob("DET-*.yaml"))
    if not sheets:
        errors.append("no rule sheet found in detections/rules")
        return
    seen_tests: set[str] = set()
    catalog_rows = {}
    catalog_path = root / "detections" / "catalog.csv"
    if catalog_path.exists():
        with catalog_path.open(encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            if reader.fieldnames != CATALOG_COLUMNS:
                errors.append(f"catalog.csv columns must be {CATALOG_COLUMNS}")
            for row in reader:
                catalog_rows[row["id"]] = row
    else:
        errors.append("detections/catalog.csv missing")

    for sheet in sheets:
        where = sheet.relative_to(root)
        rule = yaml.safe_load(sheet.read_text(encoding="utf-8"))
        missing = REQUIRED_KEYS - set(rule)
        if missing:
            errors.append(f"{where}: missing keys {sorted(missing)}")
            continue
        rid = rule["id"]
        for cid in rule["controls"]:
            if not (root / "controls" / "sheets" / f"{cid}.yaml").exists():
                errors.append(f"{where}: control {cid} has no sheet")
        if not isinstance(rule["parameters"], dict):
            errors.append(f"{where}: parameters must be a mapping, use {{}} when empty")
            continue
        if sheet.stem != rid:
            errors.append(f"{where}: id {rid} does not match file name")
        n = int(rid.split("-")[1])
        if rule["severity"] not in SEVERITIES:
            errors.append(f"{where}: severity {rule['severity']}")
        if rule["status"] not in STATUSES:
            errors.append(f"{where}: status {rule['status']}")
        for t in rule["tactics"]:
            if t not in TACTICS:
                errors.append(f"{where}: unknown tactic {t}")
        for t in rule["techniques"]:
            if not TECHNIQUE.match(t):
                errors.append(f"{where}: techniques must be parent IDs (Txxxx), got {t}")
        for t in rule["attack"]:
            if not SUBTECHNIQUE.match(t):
                errors.append(f"{where}: bad ATT&CK ID {t}")
            elif t.split(".")[0] not in rule["techniques"]:
                errors.append(f"{where}: {t} has no parent in techniques")
        for key in ("query_frequency", "query_period"):
            if not ISO_DURATION.match(str(rule[key])):
                errors.append(f"{where}: {key} is not an ISO 8601 duration")
        for ent in rule["entities"]:
            if ent.get("entity_type") not in ENTITY_TYPES:
                errors.append(f"{where}: entity type {ent.get('entity_type')}")
            for k in ("identifier", "column"):
                if not ent.get(k):
                    errors.append(f"{where}: entity without {k}")
        expected_pos, expected_neg = f"TC-{200 + 2 * n - 1}", f"TC-{200 + 2 * n}"
        tests = rule["tests"]
        for kind, expected in (("positive", expected_pos), ("negative", expected_neg)):
            tc = tests.get(kind, {})
            if tc.get("id") != expected:
                errors.append(f"{where}: {kind} test must be {expected}, got {tc.get('id')}")
            if not tc.get("steps") or not tc.get("expected"):
                errors.append(f"{where}: {kind} test needs steps and expected")
            if tc.get("id") in seen_tests:
                errors.append(f"{where}: duplicate test {tc.get('id')}")
            seen_tests.add(tc.get("id"))

        kql = rules_dir / rule["query_file"]
        if not kql.exists():
            errors.append(f"{where}: query file {rule['query_file']} missing")
        else:
            text = kql.read_text(encoding="utf-8")
            used = set(TEMPLATE_VAR.findall(text))
            declared = set((rule["parameters"] or {}).keys()) | GLOBAL_TEMPLATE_VARS
            for var in sorted(used - declared):
                errors.append(f"{kql.relative_to(root)}: template variable {var} not declared")
            for var in sorted(set((rule["parameters"] or {}).keys()) - used):
                errors.append(f"{where}: parameter {var} not used in the query")
            if "%{" in text:
                errors.append(f"{kql.relative_to(root)}: '%{{' is a Terraform template directive")
            for table in rule["data_sources"]:
                if not re.search(rf"\b{re.escape(table)}\b", text):
                    errors.append(f"{where}: data source {table} not referenced in the query")

        row = catalog_rows.pop(rid, None)
        if row is None:
            errors.append(f"catalog.csv: {rid} missing")
        else:
            expect = {
                "name": rule["name"], "severity": rule["severity"],
                "tactics": ";".join(rule["tactics"]), "attack": ";".join(rule["attack"]),
                "data_sources": ";".join(rule["data_sources"]),
                "positive_test": expected_pos, "negative_test": expected_neg,
                "status": rule["status"],
            }
            for k, v in expect.items():
                if row[k] != v:
                    errors.append(f"catalog.csv: {rid} {k} is '{row[k]}', sheet says '{v}'")
    for extra in catalog_rows:
        errors.append(f"catalog.csv: {extra} has no rule sheet")


def load_requirements(root: Path, errors: list[str]) -> dict:
    reqs = {}
    files = sorted((root / "requirements").glob("*.yaml"))
    if not files:
        errors.append("no requirement file in requirements/")
    for f in files:
        where = f.relative_to(root)
        doc = yaml.safe_load(f.read_text(encoding="utf-8"))
        for key in ("framework", "jurisdiction", "instrument", "source_url", "applies_from", "verified_on", "requirements"):
            if key not in doc:
                errors.append(f"{where}: missing file key {key}")
        if doc.get("jurisdiction") not in {"EU", "LU", "CH"}:
            errors.append(f"{where}: jurisdiction must be EU, LU or CH")
        for r in doc.get("requirements") or []:
            rid = r.get("id", "?")
            if not re.match(r"^REQ-[A-Z0-9]+-\d{2}$", rid):
                errors.append(f"{where}: bad requirement id {rid}")
            if rid in reqs:
                errors.append(f"{where}: duplicate requirement {rid}")
            for key in ("reference", "topic", "confidence", "lab_scope"):
                if not r.get(key):
                    errors.append(f"{where}: {rid} missing {key}")
            if r.get("confidence") not in CONFIDENCE:
                errors.append(f"{where}: {rid} confidence {r.get('confidence')}")
            if r.get("lab_scope") not in LAB_SCOPE:
                errors.append(f"{where}: {rid} lab_scope {r.get('lab_scope')}")
            if r.get("lab_scope") == "out" and not r.get("note"):
                errors.append(f"{where}: {rid} is out of scope without a note")
            reqs[rid] = r
    return reqs


def check_controls(root: Path, errors: list[str]) -> None:
    reqs = load_requirements(root, errors)
    with (root / "collectors" / "items.csv").open(encoding="utf-8") as fh:
        items = {r["item"] for r in csv.DictReader(fh)}
    with (root / "risk" / "risk-register.csv").open(encoding="utf-8") as fh:
        risks = {r["id"] for r in csv.DictReader(fh)}
    dets = {p.stem for p in (root / "detections" / "rules").glob("DET-*.yaml")}
    mapped: set[str] = set()
    catalog = {}
    cat_path = root / "controls" / "catalog.csv"
    if cat_path.exists():
        with cat_path.open(encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            if reader.fieldnames != CONTROL_CATALOG_COLUMNS:
                errors.append(f"controls/catalog.csv columns must be {CONTROL_CATALOG_COLUMNS}")
            catalog = {r["id"]: r for r in reader}
    else:
        errors.append("controls/catalog.csv missing")
    sheets = sorted((root / "controls" / "sheets").glob("CTL-*.yaml"))
    if not sheets:
        errors.append("no control sheet in controls/sheets")
    for sheet in sheets:
        where = sheet.relative_to(root)
        c = yaml.safe_load(sheet.read_text(encoding="utf-8"))
        missing = CONTROL_KEYS - set(c)
        if missing:
            errors.append(f"{where}: missing keys {sorted(missing)}")
            continue
        cid = c["id"]
        if sheet.stem != cid:
            errors.append(f"{where}: id {cid} does not match file name")
        n = int(cid.split("-")[1])
        if c["type"] not in CONTROL_TYPES:
            errors.append(f"{where}: type {c['type']}")
        if c["automation"] not in AUTOMATION:
            errors.append(f"{where}: automation {c['automation']}")
        if c["status"] not in STATUSES:
            errors.append(f"{where}: status {c['status']}")
        for rid in c["requirements"]:
            if rid not in reqs:
                errors.append(f"{where}: unknown requirement {rid}")
            elif reqs[rid]["lab_scope"] == "out":
                errors.append(f"{where}: maps {rid}, which is marked out of scope")
            mapped.add(rid)
        for rk in c["risks"]:
            if rk not in risks:
                errors.append(f"{where}: unknown risk {rk}")
        for e in c["evidence"]:
            if e.get("item") not in items:
                errors.append(f"{where}: evidence item {e.get('item')} not in collectors/items.csv")
        for a in c["assertions"] or []:
            if not str(a.get("id", "")).startswith(cid + "-A"):
                errors.append(f"{where}: assertion id {a.get('id')} must start with {cid}-A")
            if a.get("test") not in {"design", "effectiveness"}:
                errors.append(f"{where}: assertion {a.get('id')} test must be design or effectiveness")
        if c["automation"] != "manual" and not c["assertions"]:
            errors.append(f"{where}: {c['automation']} control without assertion")
        for d in c["detections"]:
            if d not in dets:
                errors.append(f"{where}: unknown detection {d}")
        exp = {"design": f"TC-{300 + 2 * n - 1}", "effectiveness": f"TC-{300 + 2 * n}"}
        for kind, tid in exp.items():
            tc = c["tests"].get(kind) or {}
            if tc.get("id") != tid:
                errors.append(f"{where}: {kind} test must be {tid}, got {tc.get('id')}")
            if not tc.get("steps") or not tc.get("expected"):
                errors.append(f"{where}: {kind} test needs steps and expected")
        row = catalog.pop(cid, None)
        expect = {"name": c["name"], "domain": c["domain"], "type": c["type"], "automation": c["automation"],
                  "frequency": c["frequency"], "requirements": ";".join(c["requirements"]),
                  "design_test": exp["design"], "effectiveness_test": exp["effectiveness"], "status": c["status"]}
        if row is None:
            errors.append(f"controls/catalog.csv: {cid} missing")
        else:
            for k, v in expect.items():
                if row[k] != v:
                    errors.append(f"controls/catalog.csv: {cid} {k} is '{row[k]}', sheet says '{v}'")
    for extra in catalog:
        errors.append(f"controls/catalog.csv: {extra} has no sheet")
    for rid, r in reqs.items():
        if r["lab_scope"] in {"in", "partial"} and rid not in mapped:
            errors.append(f"requirements: {rid} is '{r['lab_scope']}' but no control maps it")


def check_scenarios(root: Path, errors: list[str]) -> None:
    doc = yaml.safe_load((root / "scenarios" / "scenarios.yaml").read_text(encoding="utf-8"))
    with (root / "risk" / "risk-register.csv").open(encoding="utf-8") as fh:
        risks = {r["id"] for r in csv.DictReader(fh)}
    for s in doc["scenarios"]:
        for rk in s["risks"]:
            if rk not in risks:
                errors.append(f"scenarios.yaml: {s['id']} unknown risk {rk}")
        for cid in s["controls"]:
            if not (root / "controls" / "sheets" / f"{cid}.yaml").exists():
                errors.append(f"scenarios.yaml: {s['id']} unknown control {cid}")
        for d in s["detections"]:
            if not (root / "detections" / "rules" / f"{d}.yaml").exists():
                errors.append(f"scenarios.yaml: {s['id']} unknown detection {d}")


def check_leaks(root: Path, errors: list[str]) -> None:
    files = list(iter_files(root))
    for path in files:
        if any(path.match(pattern) for pattern in FORBIDDEN_FILES):
            errors.append(f"{path.relative_to(root)}: Terraform state, plan or tfvars must not be committed")
    for path in files:
        if path.suffix not in TEXT_SUFFIXES and path.name not in {".gitignore"}:
            continue
        rel = path.relative_to(root)
        if rel.as_posix() == "tools/validate_repo.py":
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for lineno, line in enumerate(text.splitlines(), 1):
            for m in GUID.finditer(line):
                if m.group(0).lower() not in ALLOWED_GUIDS:
                    errors.append(f"{rel}:{lineno}: GUID found (tenant, subscription or object ID?)")
            if SUB_PATH.search(line):
                errors.append(f"{rel}:{lineno}: Azure resource path with a real-looking ID")
            for m in EMAIL.finditer(line):
                domain = m.group(1).lower()
                if domain not in ALLOWED_EMAIL_DOMAINS and not domain.endswith(".example"):
                    errors.append(f"{rel}:{lineno}: e-mail address outside example domains")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", default=Path(__file__).resolve().parent.parent, type=Path)
    args = parser.parse_args()
    root = args.root.resolve()
    errors: list[str] = []
    check_controls(root, errors)
    check_rules(root, errors)
    check_scenarios(root, errors)
    check_leaks(root, errors)
    for e in errors:
        print(f"ERROR {e}")
    print(f"{len(errors)} error(s)")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
