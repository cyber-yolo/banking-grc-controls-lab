"""Evaluator tests on synthetic fixtures. Run: python -m pytest -q"""
import datetime as dt
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import evaluate_controls as ev  # noqa: E402

AS_OF = dt.date(2026, 12, 3)
# Assertions that read repository files only: same result for both fixture sets.
REPO_ONLY = {"CTL-007-A2", "CTL-014-A1", "CTL-014-A2", "CTL-016-A1"}
# Assertions that also need the detection test matrix to show PASS rows,
# which is NOT RUN at v0.1.
MATRIX_DEPENDENT = {"CTL-011-A3"}


def results(fixture):
    res = ev.evaluate(ROOT, ROOT / "tests" / "fixtures" / fixture, AS_OF)
    return {a["id"]: a for c in res["controls"] for a in c["assertions"]}


def declared():
    return {a["id"] for c in ev.load_controls(ROOT) for a in c.get("assertions") or []}


def test_every_declared_assertion_is_implemented():
    assert declared() <= set(ev.ASSERTIONS), declared() - set(ev.ASSERTIONS)


def test_every_implementation_is_declared():
    assert set(ev.ASSERTIONS) <= declared(), set(ev.ASSERTIONS) - declared()


def test_pass_fixture_all_pass():
    for aid, a in results("pass").items():
        if aid in REPO_ONLY:
            continue  # depends on repository content, checked in its own tests
        if aid in MATRIX_DEPENDENT:
            assert a["status"] == ev.FAIL, (aid, a)  # honest: no detection test has run yet
        else:
            assert a["status"] == ev.PASS, (aid, a)


def test_fail_fixture_all_fail():
    for aid, a in results("fail").items():
        if aid in REPO_ONLY:
            continue
        assert a["status"] == ev.FAIL, (aid, a)


def test_no_run_gives_no_evidence_not_pass():
    res = ev.evaluate(ROOT, None, AS_OF)
    for c in res["controls"]:
        for a in c["assertions"]:
            if a["id"] not in REPO_ONLY:
                assert a["status"] == ev.NO_EVIDENCE, a


def test_details_mask_user_domains():
    for a in results("fail").values():
        assert "contoso.example" not in a["detail"], a


def test_repository_checks_pass_except_pending_decisions():
    res = ev.evaluate(ROOT, None, AS_OF)
    a = {x["id"]: x for c in res["controls"] for x in c["assertions"]}
    for aid in ("CTL-007-A2", "CTL-014-A1", "CTL-014-A2"):
        assert a[aid]["status"] == ev.PASS, a[aid]
    # Decision dates are left for the maintainer to fill: FAIL until then.
    assert a["CTL-016-A1"]["status"] in (ev.PASS, ev.FAIL)


def test_register_assessment_expiry():
    res = ev.evaluate(ROOT, None, dt.date(2028, 1, 1))
    a = {x["id"]: x for c in res["controls"] for x in c["assertions"]}["CTL-014-A2"]
    assert a["status"] == ev.FAIL


# ---------- PIM, access reviews and cloud posture (CTL-003, CTL-005, CTL-015) ----------

import csv  # noqa: E402
import json  # noqa: E402
import shutil  # noqa: E402

import validate_repo  # noqa: E402


def run_with(tmp_path, changes, base="pass"):
    """Copy a fixture set, apply changes {file: function(value list) -> value list}, return results."""
    run = tmp_path / "run"
    shutil.copytree(ROOT / "tests" / "fixtures" / base, run)
    for name, fn in changes.items():
        path = run / name
        env = json.loads(path.read_text(encoding="utf-8"))
        env["value"] = fn(env["value"])
        path.write_text(json.dumps(env), encoding="utf-8")
    res = ev.evaluate(ROOT, run, AS_OF)
    return {a["id"]: a for c in res["controls"] for a in c["assertions"]}


def repo_copy(tmp_path):
    root = tmp_path / "repo"
    shutil.copytree(ROOT, root, ignore=shutil.ignore_patterns(".git", ".terraform", "evidence", "__pycache__", ".pytest_cache"))
    return root


def write_register(root, rows):
    path = root / "posture" / "remediation-register.csv"
    with path.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=validate_repo.REMEDIATION_COLUMNS, lineterminator="\n")
        w.writeheader()
        for r in rows:
            w.writerow({c: r.get(c, "") for c in validate_repo.REMEDIATION_COLUMNS})


def test_iso_duration():
    assert ev.iso_duration("PT4H") == dt.timedelta(hours=4)
    assert ev.iso_duration("PT30M") == dt.timedelta(minutes=30)
    assert ev.iso_duration("P365D") == dt.timedelta(days=365)
    assert ev.iso_duration("P1Y") == dt.timedelta(days=365)
    assert ev.iso_duration("P") is None and ev.iso_duration(None) is None and ev.iso_duration("4 hours") is None


def test_pim_eligibility_over_one_year_fails(tmp_path):
    def longer(policies):
        for pa in policies:
            for r in pa["policy"]["rules"]:
                if r["id"] == "Expiration_Admin_Eligibility":
                    r["maximumDuration"] = "P2Y"
        return policies
    a = run_with(tmp_path, {"role-management-policies.json": longer})
    assert a["CTL-003-A7"]["status"] == ev.FAIL and "P2Y" in a["CTL-003-A7"]["detail"]


def test_pim_approval_without_approver_fails(tmp_path):
    def no_approver(policies):
        for pa in policies:
            for r in pa["policy"]["rules"]:
                if r["id"] == "Approval_EndUser_Assignment":
                    r["setting"]["approvalStages"] = [{"primaryApprovers": []}]
        return policies
    a = run_with(tmp_path, {"role-management-policies.json": no_approver})
    assert a["CTL-003-A6"]["status"] == ev.FAIL and "no approver" in a["CTL-003-A6"]["detail"]


def test_access_review_weak_settings_fail(tmp_path):
    def weaken(defs):
        d = defs[0]
        d["settings"]["autoApplyDecisionsEnabled"] = False
        d["settings"]["defaultDecision"] = "None"
        d["reviewers"] = [{"query": "./principal", "queryType": "MicrosoftGraph"}]
        d["instances"] = [{"status": "Applied", "endDateTime": "2026-05-01T08:00:00Z"}]
        return defs
    a = run_with(tmp_path, {"access-review-definitions.json": weaken})
    for aid in ("CTL-005-A3", "CTL-005-A4", "CTL-005-A5"):
        assert a[aid]["status"] == ev.FAIL, a[aid]
    assert a["CTL-005-A1"]["status"] == ev.PASS


def test_defender_without_cloud_posture_plan_fails(tmp_path):
    a = run_with(tmp_path, {"defender-plans.json": lambda plans: [p for p in plans if p["name"] != "CloudPosture"]})
    assert a["CTL-015-A3"]["status"] == ev.FAIL


def test_empty_assessments_give_no_evidence(tmp_path):
    a = run_with(tmp_path, {"security-assessments.json": lambda _: []})
    assert a["CTL-015-A5"]["status"] == ev.NO_EVIDENCE
    assert a["CTL-015-A6"]["status"] == ev.NO_EVIDENCE


def test_closed_remediation_still_unhealthy_fails(tmp_path):
    root = repo_copy(tmp_path)
    write_register(root, [
        {"id": "REM-001", "recommendation": "Accounts with owner permissions on Azure resources should be MFA enabled",
         "decision": "fix", "owner_role": "IAM engineering", "status": "closed", "closed_on": "2026-12-01", "origin": "anticipated"},
        {"id": "REM-002", "recommendation": "There should be more than one owner assigned to subscriptions",
         "decision": "fix", "owner_role": "Cloud platform engineering", "status": "open", "origin": "anticipated"},
    ])
    res = ev.evaluate(root, ROOT / "tests" / "fixtures" / "pass", AS_OF)
    a = {x["id"]: x for c in res["controls"] for x in c["assertions"]}["CTL-015-A6"]
    assert a["status"] == ev.FAIL and "REM-001 (closed but still unhealthy" in a["detail"]


def test_acceptance_needs_risk_record(tmp_path):
    root = repo_copy(tmp_path)
    rows = [
        {"id": "REM-001", "recommendation": "Accounts with owner permissions on Azure resources should be MFA enabled",
         "decision": "accept", "owner_role": "IAM engineering", "risk_acceptance": "RA-999", "status": "open", "origin": "anticipated"},
        {"id": "REM-002", "recommendation": "There should be more than one owner assigned to subscriptions",
         "decision": "fix", "owner_role": "Cloud platform engineering", "status": "open", "origin": "anticipated"},
    ]
    write_register(root, rows)
    res = ev.evaluate(root, ROOT / "tests" / "fixtures" / "pass", AS_OF)
    a = {x["id"]: x for c in res["controls"] for x in c["assertions"]}["CTL-015-A6"]
    assert a["status"] == ev.FAIL and "RA-999" not in a["detail"] and "risk acceptance record" in a["detail"]
    errors = []
    validate_repo.check_remediation(root, errors)
    assert any("risk acceptance record" in e for e in errors), errors


def test_remediation_register_in_repository_is_valid():
    errors = []
    validate_repo.check_remediation(ROOT, errors)
    assert errors == []
