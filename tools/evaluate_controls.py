#!/usr/bin/env python3
"""Evaluate control assertions against collected evidence.

Reads one evidence run (folder written by collectors/Collect-Evidence.ps1) and
the repository files, runs every machine-checkable assertion declared in
controls/sheets/CTL-*.yaml and writes a results file.

Each assertion returns PASS, FAIL or NO_EVIDENCE with a short detail. The
evaluator never guesses: a missing or failed evidence item gives NO_EVIDENCE.
Details never contain full user principal names (domain masked).

Usage:
  python tools/evaluate_controls.py                      # repository-only assertions
  python tools/evaluate_controls.py --run evidence/runs/20261203T1405Z
  python tools/evaluate_controls.py --run DIR --out reports/results.json --as-of 2026-12-03
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent

# Microsoft Graph's well-known public application ID (same in every tenant).
GRAPH_APP_ID = "00000003-0000-0000-c000-000000000000"
BREAK_GLASS_PREFIX = "bg-"
TIER0_ROLES = {
    "Global Administrator", "Privileged Role Administrator",
    "Privileged Authentication Administrator", "Security Administrator",
}
# Graph application permissions treated as high-risk (lab list, to review).
HIGH_RISK_APP_PERMISSIONS = {
    "Application.ReadWrite.All", "AppRoleAssignment.ReadWrite.All", "Directory.ReadWrite.All",
    "RoleManagement.ReadWrite.Directory", "Policy.ReadWrite.ConditionalAccess", "User.ReadWrite.All",
    "Mail.ReadWrite", "Mail.Send", "Files.ReadWrite.All", "Sites.FullControl.All",
}
SECRET_MAX_DAYS = 180
MFA_TARGET = 0.99
RETENTION_TARGET_DAYS = 90
SECURE_SCORE_TARGET = 0.70
# PIM role settings (CTL-003). Lab targets, not regulatory thresholds.
PIM_MAX_ACTIVATION = dt.timedelta(hours=4)
PIM_MAX_ELIGIBILITY = dt.timedelta(days=365)
PIM_APPROVAL_ROLES = {"Global Administrator", "Privileged Role Administrator"}
GLOBAL_ADMIN_MAX = 4  # Microsoft recommends fewer than five Global Administrators
# Access review settings (CTL-005).
REVIEW_MAX_AGE_DAYS = 92
REVIEW_DONE_STATUSES = {"Completed", "Applied", "AutoReviewed"}
# Defender for Cloud (CTL-015).
# Public ID of the built-in "Microsoft cloud security benchmark" initiative, the
# same in every tenant (TO VERIFY on the first run; display name used as fallback).
MCSB_SET_ID = "1f3afdf9-d0c9-4c3d-847f-89da613e70a8"
MCSB_NAME = "microsoft cloud security benchmark"
REMEDIATION_SLA_DAYS = {"High": 30, "Medium": 90, "Low": 180}  # lab choice, from first evaluation
TRACKED_SEVERITIES = {"High", "Medium"}
REQUIRED_TABLES = {"SigninLogs", "AuditLogs", "OfficeActivity", "AzureActivity", "SecurityAlert"}
REGISTER_COLUMNS = [
    "id", "provider", "service", "ict_service_type", "supports_critical_function", "data_location",
    "data_categories", "contract_reference", "subcontractors_known", "substitutability", "exit_plan_ref",
    "last_assessment", "status",
]
REGISTER_MANDATORY = [c for c in REGISTER_COLUMNS if c not in {"exit_plan_ref"}]

PASS, FAIL, NO_EVIDENCE = "PASS", "FAIL", "NO_EVIDENCE"


class NoEvidence(Exception):
    """Raised when an evidence item is missing, failed or empty."""


class Context:
    def __init__(self, root: Path, run: Path | None, as_of: dt.date):
        self.root, self.run, self.as_of = root, run, as_of
        with (root / "collectors" / "items.csv").open(encoding="utf-8") as fh:
            self.items = {r["item"]: r for r in csv.DictReader(fh)}

    def evidence(self, item: str) -> list:
        row = self.items[item]
        if row["method"] == "repo":
            raise ValueError(f"{item} is a repository file, use repo_csv()")
        if self.run is None:
            raise NoEvidence(f"{item}: no evidence run given")
        path = self.run / row["output"]
        if not path.exists():
            raise NoEvidence(f"{item}: {row['output']} not in run")
        data = json.loads(path.read_text(encoding="utf-8-sig"))
        if data.get("status") != "ok":
            raise NoEvidence(f"{item}: collection status {data.get('status')}")
        return data.get("value") or []

    def repo_csv(self, item: str) -> list[dict]:
        path = self.root / self.items[item]["target"]
        if not path.exists():
            raise NoEvidence(f"{item}: {path.name} missing")
        with path.open(encoding="utf-8") as fh:
            return list(csv.DictReader(fh))

    def repo_yaml(self, rel: str):
        return yaml.safe_load((self.root / rel).read_text(encoding="utf-8"))


ASSERTIONS = {}


def assertion(aid):
    def wrap(fn):
        ASSERTIONS[aid] = fn
        return fn
    return wrap


def mask(upn: str | None) -> str:
    if not upn:
        return "<unknown>"
    return upn.split("@")[0] + "@<lab-domain>" if "@" in upn else upn


def g(obj, *path, default=None):
    """Safe nested get for dicts."""
    for key in path:
        if not isinstance(obj, dict):
            return default
        obj = obj.get(key)
        if obj is None:
            return default
    return obj


def parse_ts(text: str) -> dt.datetime:
    return dt.datetime.fromisoformat(text.replace("Z", "+00:00"))


ISO_DURATION = re.compile(r"^P(?:(\d+)Y)?(?:(\d+)M)?(?:(\d+)W)?(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?$")


def iso_duration(text: str | None) -> dt.timedelta | None:
    """ISO 8601 duration (PT4H, P365D, P1Y) to timedelta. Years count 365 days, months 30."""
    m = ISO_DURATION.match(text or "")
    if not m or not any(m.groups()):
        return None
    y, mo, w, d, h, mi, sec = (int(x or 0) for x in m.groups())
    return dt.timedelta(days=365 * y + 30 * mo + 7 * w + d, hours=h, minutes=mi, seconds=sec)


def names(values) -> str:
    values = sorted(values)
    return ", ".join(values[:10]) + (f" (+{len(values) - 10} more)" if len(values) > 10 else "")


# ---------- Conditional Access (CTL-001, CTL-002, CTL-004) ----------

def mfa_all_policies(policies, state="enabled"):
    out = []
    for p in policies:
        grants = g(p, "grantControls", default={}) or {}
        requires_mfa = "mfa" in (grants.get("builtInControls") or []) or grants.get("authenticationStrength")
        if (p.get("state") == state and requires_mfa
                and "All" in (g(p, "conditions", "users", "includeUsers", default=[]))
                and "All" in (g(p, "conditions", "applications", "includeApplications", default=[]))):
            out.append(p)
    return out


@assertion("CTL-001-A1")
def ctl001_a1(ctx):
    policies = ctx.evidence("ConditionalAccessPolicies")
    found = mfa_all_policies(policies)
    if found:
        return PASS, f"enabled: {names(p['displayName'] for p in found)}"
    report_only = mfa_all_policies(policies, "enabledForReportingButNotEnforced")
    hint = f"; report-only only: {names(p['displayName'] for p in report_only)}" if report_only else ""
    return FAIL, "no enabled MFA policy for all users and all apps" + hint


@assertion("CTL-001-A2")
def ctl001_a2(ctx):
    found = mfa_all_policies(ctx.evidence("ConditionalAccessPolicies"))
    if not found:
        return FAIL, "no enabled MFA policy to check (see CTL-001-A1)"
    bad = []
    for p in found:
        users = g(p, "conditions", "users", default={})
        if (users.get("excludeGroups") or []) or len(users.get("excludeUsers") or []) > 2 or (users.get("excludeRoles") or []):
            bad.append(p["displayName"])
    return (FAIL, f"too broad exclusions: {names(bad)}") if bad else (PASS, f"{len(found)} policy(ies), exclusions within limit")


@assertion("CTL-001-A3")
def ctl001_a3(ctx):
    rows = ctx.evidence("KqlMfaCoverage")
    total = int(rows[0].get("total", 0)) if rows else 0
    if total == 0:
        raise NoEvidence("KqlMfaCoverage: no successful interactive sign-in in the window")
    mfa = int(rows[0].get("mfa", 0))
    ratio = mfa / total
    status = PASS if ratio >= MFA_TARGET else FAIL
    return status, f"{mfa}/{total} sign-ins with MFA ({ratio:.1%}, target {MFA_TARGET:.0%})"


@assertion("CTL-002-A1")
def ctl002_a1(ctx):
    for p in ctx.evidence("ConditionalAccessPolicies"):
        apps = set(g(p, "conditions", "clientAppTypes", default=[]))
        if (p.get("state") == "enabled" and {"exchangeActiveSync", "other"} <= apps
                and "block" in (g(p, "grantControls", "builtInControls", default=[]))
                and "All" in g(p, "conditions", "users", "includeUsers", default=[])):
            return PASS, f"blocking policy: {p['displayName']}"
    return FAIL, "no enabled policy blocks exchangeActiveSync and other clients for all users"


@assertion("CTL-002-A2")
def ctl002_a2(ctx):
    rows = ctx.evidence("KqlLegacyAuth")
    success = int(rows[0].get("legacy_success", 0)) if rows else 0
    attempts = int(rows[0].get("attempts", 0)) if rows else 0
    return (PASS if success == 0 else FAIL), f"{success} successful of {attempts} legacy attempts over 7 days"


def break_glass_users(ctx):
    return [u for u in ctx.evidence("BreakGlassUsers")
            if (u.get("userPrincipalName") or "").lower().startswith(BREAK_GLASS_PREFIX)]


@assertion("CTL-004-A1")
def ctl004_a1(ctx):
    users = break_glass_users(ctx)
    enabled = [u for u in users if u.get("accountEnabled")]
    ok = len(users) == 2 and len(enabled) == 2
    return (PASS if ok else FAIL), f"{len(users)} break-glass account(s), {len(enabled)} enabled (expected 2 and 2)"


@assertion("CTL-004-A2")
def ctl004_a2(ctx):
    ids = {u["id"] for u in break_glass_users(ctx)}
    if not ids:
        return FAIL, "no break-glass account to check"
    missing = [p["displayName"] for p in ctx.evidence("ConditionalAccessPolicies")
               if p.get("state") in ("enabled", "enabledForReportingButNotEnforced")
               and not ids <= set(g(p, "conditions", "users", "excludeUsers", default=[]))]
    return (FAIL, f"policies not excluding both: {names(missing)}") if missing else (PASS, "all active policies exclude both")


# ---------- Privileged access (CTL-003, CTL-005) ----------

def role_names(ctx):
    return {r["id"]: r["displayName"] for r in ctx.evidence("RoleDefinitions")}


@assertion("CTL-003-A1")
def ctl003_a1(ctx):
    roles = role_names(ctx)
    bad = []
    for a in ctx.evidence("RoleAssignmentInstances"):
        role = roles.get(a.get("roleDefinitionId"), a.get("roleDefinitionId"))
        if role in TIER0_ROLES and a.get("assignmentType") == "Assigned" and not a.get("endDateTime"):
            upn = g(a, "principal", "userPrincipalName") or g(a, "principal", "displayName") or a.get("principalId")
            if not str(upn).lower().startswith(BREAK_GLASS_PREFIX):
                bad.append(f"{mask(upn)} ({role})")
    return (FAIL, f"permanent tier-0: {names(bad)}") if bad else (PASS, "no permanent tier-0 assignment outside break-glass")


@assertion("CTL-003-A2")
def ctl003_a2(ctx):
    roles = role_names(ctx)
    eligible = [e for e in ctx.evidence("RoleEligibilityInstances") if roles.get(e.get("roleDefinitionId")) in TIER0_ROLES]
    return (PASS if eligible else FAIL), f"{len(eligible)} eligible tier-0 assignment(s)"


@assertion("CTL-003-A3")
def ctl003_a3(ctx):
    rows = ctx.evidence("KqlPimActivations")
    total = int(rows[0].get("activations", 0)) if rows else 0
    if total == 0:
        raise NoEvidence("KqlPimActivations: no activation in the window")
    missing = int(rows[0].get("without_justification", 0))
    return (PASS if missing == 0 else FAIL), f"{total} activation(s), {missing} without justification"


# PIM role settings: one policy per directory role, rules identified by id.
# Rule ids are Microsoft's fixed names (Enablement_EndUser_Assignment, ...).

def tier0_role_rules(ctx) -> dict[str, dict | None]:
    """Tier-0 role name -> {rule id: rule}, or None when no policy was collected for it."""
    roles = role_names(ctx)
    out: dict[str, dict | None] = {name: None for name in roles.values() if name in TIER0_ROLES}
    for pa in ctx.evidence("RoleManagementPolicies"):
        name = roles.get(pa.get("roleDefinitionId"))
        if name in TIER0_ROLES:
            out[name] = {r.get("id"): r for r in g(pa, "policy", "rules", default=[]) or []}
    if not out:
        raise NoEvidence("RoleDefinitions: no tier-0 role found")
    return out


def check_roles(rules_by_role: dict, check) -> tuple[str, str]:
    """Run check(rules) -> problem text or None on each role; FAIL lists the roles with a problem."""
    bad = []
    for role, rules in sorted(rules_by_role.items()):
        problem = "no PIM policy collected" if rules is None else check(rules)
        if problem:
            bad.append(f"{role} ({problem})")
    return (FAIL, names(bad)) if bad else (PASS, f"{len(rules_by_role)} tier-0 role(s) checked")


@assertion("CTL-003-A4")
def ctl003_a4(ctx):
    def check(rules):
        enabled = set(g(rules, "Enablement_EndUser_Assignment", "enabledRules", default=[]) or [])
        auth_context = bool(g(rules, "AuthenticationContext_EndUser_Assignment", "isEnabled", default=False))
        missing = ([] if ("MultiFactorAuthentication" in enabled or auth_context) else ["MFA"]) + \
                  ([] if "Justification" in enabled else ["justification"])
        return "no " + " and no ".join(missing) + " on activation" if missing else None
    return check_roles(tier0_role_rules(ctx), check)


@assertion("CTL-003-A5")
def ctl003_a5(ctx):
    def check(rules):
        raw = g(rules, "Expiration_EndUser_Assignment", "maximumDuration")
        limit = iso_duration(raw)
        if limit is None:
            return "maximum activation duration not readable"
        return None if limit <= PIM_MAX_ACTIVATION else f"activation up to {raw}"
    return check_roles(tier0_role_rules(ctx), check)


@assertion("CTL-003-A6")
def ctl003_a6(ctx):
    def check(rules):
        setting = g(rules, "Approval_EndUser_Assignment", "setting", default={}) or {}
        approvers = [a for st in setting.get("approvalStages") or [] for a in st.get("primaryApprovers") or []]
        if not setting.get("isApprovalRequired"):
            return "approval not required"
        return None if approvers else "approval required but no approver"
    scope = {k: v for k, v in tier0_role_rules(ctx).items() if k in PIM_APPROVAL_ROLES}
    if not scope:
        raise NoEvidence("RoleDefinitions: Global Administrator and Privileged Role Administrator not found")
    return check_roles(scope, check)


@assertion("CTL-003-A7")
def ctl003_a7(ctx):
    def check(rules):
        rule = rules.get("Expiration_Admin_Eligibility") or {}
        if not rule.get("isExpirationRequired"):
            return "permanent eligibility allowed"
        limit = iso_duration(rule.get("maximumDuration"))
        return None if limit is not None and limit <= PIM_MAX_ELIGIBILITY else f"eligibility up to {rule.get('maximumDuration')}"
    return check_roles(tier0_role_rules(ctx), check)


def principal_key(a: dict) -> str:
    return str(g(a, "principal", "userPrincipalName") or g(a, "principal", "displayName") or a.get("principalId"))


@assertion("CTL-003-A8")
def ctl003_a8(ctx):
    roles = role_names(ctx)
    holders = {principal_key(a) for item in ("RoleAssignmentInstances", "RoleEligibilityInstances")
               for a in ctx.evidence(item) if roles.get(a.get("roleDefinitionId")) == "Global Administrator"}
    status = PASS if 0 < len(holders) <= GLOBAL_ADMIN_MAX else FAIL
    return status, f"{len(holders)} Global Administrator holder(s), active or eligible, break-glass included (maximum {GLOBAL_ADMIN_MAX})"


@assertion("CTL-003-A9")
def ctl003_a9(ctx):
    rows = ctx.evidence("KqlDirectPrivilegedAssignments")
    direct = int(rows[0].get("direct_assignments", 0)) if rows else 0
    return (PASS if direct == 0 else FAIL), f"{direct} tier-0 assignment(s) made outside PIM over 30 days"


def months_between_runs(pattern: dict) -> float | None:
    kind, interval = (pattern.get("type") or "").lower(), pattern.get("interval") or 1
    if "monthly" in kind:
        return float(interval)
    if kind == "weekly":
        return interval * 7 / 30.4
    if "yearly" in kind:
        return 12.0 * interval
    return None


def role_reviews(ctx):
    return [d for d in ctx.evidence("AccessReviewDefinitions") if "rolemanagement" in json.dumps(d.get("scope", {})).lower()]


@assertion("CTL-005-A1")
def ctl005_a1(ctx):
    hits = role_reviews(ctx)
    return (PASS, f"role reviews: {names(d['displayName'] for d in hits)}") if hits else (FAIL, "no access review on directory roles")


@assertion("CTL-005-A2")
def ctl005_a2(ctx):
    hits = role_reviews(ctx)
    if not hits:
        return FAIL, "no role review to check (see CTL-005-A1)"
    for d in hits:
        months = months_between_runs(g(d, "settings", "recurrence", "pattern", default={}))
        if months is not None and months <= 3:
            return PASS, f"{d['displayName']}: every {months:.1f} month(s)"
    return FAIL, "no role review recurs at least quarterly"


@assertion("CTL-005-A3")
def ctl005_a3(ctx):
    hits = role_reviews(ctx)
    if not hits:
        return FAIL, "no role review to check (see CTL-005-A1)"
    bad = []
    for d in hits:
        st = d.get("settings") or {}
        missing = [label for label, ok in (
            ("auto-apply", st.get("autoApplyDecisionsEnabled") is True),
            ("deny when no response", st.get("defaultDecisionEnabled") is True and st.get("defaultDecision") == "Deny"),
            ("justification on approval", st.get("justificationRequiredOnApproval") is True),
        ) if not ok]
        if missing:
            bad.append(f"{d['displayName']} (missing {', '.join(missing)})")
    return (FAIL, names(bad)) if bad else (PASS, f"{len(hits)} role review(s) remove unconfirmed access")


def is_self_review(reviewers: list) -> bool:
    # Representation of self-review for role reviews TO VERIFY on the first run.
    return any("principal" in (r.get("query") or "").lower() and "/users/" not in (r.get("query") or "").lower()
               for r in reviewers)


@assertion("CTL-005-A4")
def ctl005_a4(ctx):
    hits = role_reviews(ctx)
    if not hits:
        return FAIL, "no role review to check (see CTL-005-A1)"
    bad = [d["displayName"] for d in hits if not (d.get("reviewers") or []) or is_self_review(d.get("reviewers") or [])]
    return (FAIL, f"no independent reviewer: {names(bad)}") if bad else (PASS, "reviewers named, no self-review")


@assertion("CTL-005-A5")
def ctl005_a5(ctx):
    hits = role_reviews(ctx)
    if not hits:
        return FAIL, "no role review to check (see CTL-005-A1)"
    done = []
    for d in hits:
        for inst in d.get("instances") or []:
            if inst.get("status") in REVIEW_DONE_STATUSES and inst.get("endDateTime"):
                age = (ctx.as_of - parse_ts(inst["endDateTime"]).date()).days
                if 0 <= age <= REVIEW_MAX_AGE_DAYS:
                    done.append((age, d["displayName"], inst["status"]))
    if not done:
        return FAIL, f"no role review instance completed in the last {REVIEW_MAX_AGE_DAYS} days"
    age, name, status = min(done)
    return PASS, f"{name}: last instance {status} {age} day(s) before {ctx.as_of}"


# ---------- Non-human and AI agent identities (CTL-006, CTL-007) ----------

def graph_permission_names(ctx):
    roles = {}
    for sp in ctx.evidence("GraphAppRoles"):
        for r in sp.get("appRoles") or []:
            roles[r["id"]] = r["value"]
    return roles


def high_risk_requested(app, perm_names):
    out = set()
    for res in app.get("requiredResourceAccess") or []:
        if res.get("resourceAppId") != GRAPH_APP_ID:
            continue
        for acc in res.get("resourceAccess") or []:
            name = perm_names.get(acc.get("id"))
            if acc.get("type") == "Role" and name in HIGH_RISK_APP_PERMISSIONS:
                out.add(name)
    return out


def has_tag(app, tag):
    return tag in (app.get("tags") or [])


@assertion("CTL-006-A1")
def ctl006_a1(ctx):
    apps = ctx.evidence("Applications")
    orphans = [a["displayName"] for a in apps if not a.get("owners")]
    return (FAIL, f"no owner: {names(orphans)}") if orphans else (PASS, f"{len(apps)} app(s), all owned")


@assertion("CTL-006-A2")
def ctl006_a2(ctx):
    bad = []
    for a in ctx.evidence("Applications"):
        for c in a.get("passwordCredentials") or []:
            days = (parse_ts(c["endDateTime"]) - parse_ts(c["startDateTime"])).days
            if days > SECRET_MAX_DAYS:
                bad.append(f"{a['displayName']} ({days} d)")
    return (FAIL, f"secrets above {SECRET_MAX_DAYS} days: {names(bad)}") if bad else (PASS, f"no secret above {SECRET_MAX_DAYS} days")


@assertion("CTL-006-A3")
def ctl006_a3(ctx):
    perms = graph_permission_names(ctx)
    bad = []
    for a in ctx.evidence("Applications"):
        risky = high_risk_requested(a, perms)
        accepted = any(t.startswith("grc-ra:") for t in a.get("tags") or [])
        if risky and not accepted:
            bad.append(f"{a['displayName']} ({', '.join(sorted(risky))})")
    return (FAIL, f"high-risk without RA: {names(bad)}") if bad else (PASS, "no high-risk application permission without RA")


def inventory(ctx):
    return [r for r in ctx.repo_csv("AiSystemInventory") if r["status"] != "retired"]


@assertion("CTL-007-A1")
def ctl007_a1(ctx):
    tagged = {a["displayName"] for a in ctx.evidence("Applications") if has_tag(a, "ai-agent")}
    rows = inventory(ctx)
    listed = {r["entra_app_name"] for r in rows if r["entra_app_name"]}
    live = {r["entra_app_name"] for r in rows if r["entra_app_name"] and r["status"] == "live"}
    shadow, ghost = tagged - listed, live - tagged
    problems = ([f"not inventoried: {names(shadow)}"] if shadow else []) + ([f"inventoried as live but absent: {names(ghost)}"] if ghost else [])
    return (FAIL, "; ".join(problems)) if problems else (PASS, f"{len(tagged)} tagged agent(s), all inventoried")


@assertion("CTL-007-A2")
def ctl007_a2(ctx):
    bad = []
    for r in inventory(ctx):
        if (not r["owner_role"] or r["ai_act_role"] not in {"provider", "deployer"}
                or r["ai_act_risk_class"] not in {"prohibited", "high", "limited", "minimal"} or not r["human_oversight"]):
            bad.append(r["id"])
    return (FAIL, f"incomplete entries: {names(bad)}") if bad else (PASS, "all inventory entries complete")


@assertion("CTL-007-A3")
def ctl007_a3(ctx):
    perms = graph_permission_names(ctx)
    bad = [f"{a['displayName']} ({', '.join(sorted(high_risk_requested(a, perms)))})"
           for a in ctx.evidence("Applications") if has_tag(a, "ai-agent") and high_risk_requested(a, perms)]
    return (FAIL, f"agents with high-risk permissions: {names(bad)}") if bad else (PASS, "no agent with high-risk permission")


# ---------- Data protection (CTL-009) ----------

@assertion("CTL-009-A1")
def ctl009_a1(ctx):
    pol = [p for p in ctx.evidence("DlpPolicies") if p.get("Name") == "PV-POL-001"]
    if not pol:
        return FAIL, "PV-POL-001 not found"
    p = pol[0]
    exchange_all = "all" in json.dumps(p.get("ExchangeLocation")).lower()
    ok = p.get("Mode") == "Enable" and exchange_all
    return (PASS if ok else FAIL), f"mode {p.get('Mode')}, Exchange all mailboxes: {exchange_all}"


@assertion("CTL-009-A2")
def ctl009_a2(ctx):
    for r in ctx.evidence("DlpRules"):
        if (r.get("ParentPolicyName") == "PV-POL-001" and not r.get("Disabled")
                and r.get("AccessScope") == "NotInOrganization"
                and "iban" in json.dumps(r.get("ContentContainsSensitiveInformation")).lower()):
            return PASS, f"rule {r.get('Name')}"
    return FAIL, "no enabled PV-POL-001 rule on IBAN for external recipients"


# ---------- Logging and detection (CTL-010, CTL-011) ----------

@assertion("CTL-010-A1")
def ctl010_a1(ctx):
    for s in ctx.evidence("EntraDiagnosticSettings"):
        props = s.get("properties", {})
        enabled = {l.get("category") for l in props.get("logs") or [] if l.get("enabled")}
        if props.get("workspaceId") and {"SignInLogs", "AuditLogs"} <= enabled:
            return PASS, f"setting {s.get('name')}"
    return FAIL, "no Entra diagnostic setting with SignInLogs and AuditLogs to a workspace"


@assertion("CTL-010-A2")
def ctl010_a2(ctx):
    ws = ctx.evidence("Workspace")
    days = int(ws[0].get("retentionInDays", 0)) if ws else 0
    return (PASS if days >= RETENTION_TARGET_DAYS else FAIL), f"retention {days} days (lab target {RETENTION_TARGET_DAYS}, see RA-001)"


@assertion("CTL-010-A3")
def ctl010_a3(ctx):
    seen = {r["TableName"] for r in ctx.evidence("KqlTableFreshness") if int(r.get("rows", 0)) > 0}
    missing = REQUIRED_TABLES - seen
    return (FAIL, f"no rows in 24 h: {names(missing)}") if missing else (PASS, "all five tables fresh")


def deployed_rules(ctx):
    """DET-xxx -> enabled flag, from the Sentinel export."""
    out = {}
    for r in ctx.evidence("SentinelAlertRules"):
        name = g(r, "properties", "displayName", default="")
        if name.startswith("DET-"):
            out[name[:7]] = bool(g(r, "properties", "enabled", default=False))
    return out


@assertion("CTL-011-A1")
def ctl011_a1(ctx):
    deployed = deployed_rules(ctx)
    if not deployed:
        return FAIL, "no DET rule deployed"
    sheets = {p.stem for p in (ctx.root / "detections" / "rules").glob("DET-*.yaml")}
    unknown = set(deployed) - sheets
    disabled = {k for k, v in deployed.items() if not v}
    problems = ([f"no sheet: {names(unknown)}"] if unknown else []) + ([f"disabled: {names(disabled)}"] if disabled else [])
    return (FAIL, "; ".join(problems)) if problems else (PASS, f"{len(deployed)} rule(s) deployed and enabled")


@assertion("CTL-011-A2")
def ctl011_a2(ctx):
    active = {k for k, v in deployed_rules(ctx).items() if v}
    uncovered = [s["id"] for s in ctx.repo_yaml("scenarios/scenarios.yaml")["scenarios"] if not set(s["detections"]) & active]
    return (FAIL, f"scenarios without active rule: {names(uncovered)}") if uncovered else (PASS, "every scenario covered")


@assertion("CTL-011-A3")
def ctl011_a3(ctx):
    active = {k for k, v in deployed_rules(ctx).items() if v}
    if not active:
        return FAIL, "no active rule"
    passed = {r["object_id"] for r in ctx.repo_csv("DetectionTestMatrix") if r["type"] == "positive" and r["status"] == "PASS"}
    missing = active - passed
    return (FAIL, f"no positive PASS: {names(missing)}") if missing else (PASS, f"{len(active)} rule(s) with positive PASS")


# ---------- Data residency (CTL-013) ----------

@assertion("CTL-013-A1")
def ctl013_a1(ctx):
    found = [a for a in ctx.evidence("PolicyAssignments") if (a.get("displayName") or "").startswith("CTL-013")]
    enforced = [a for a in found if a.get("enforcementMode", "Default") == "Default"]
    ok = len(found) >= 2 and len(enforced) == len(found)
    return (PASS if ok else FAIL), f"{len(found)} CTL-013 assignment(s), {len(enforced)} enforced (expected 2)"


@assertion("CTL-013-A2")
def ctl013_a2(ctx):
    summary = ctx.evidence("PolicyComplianceSummary")
    assignments = [a for s in summary for a in s.get("policyAssignments") or []
                   if "ctl-013" in (a.get("policyAssignmentId") or "").lower()]
    if not assignments:
        raise NoEvidence("PolicyComplianceSummary: CTL-013 assignments not in summary yet")
    bad = sum(int(g(a, "results", "nonCompliantResources", default=0)) for a in assignments)
    return (PASS if bad == 0 else FAIL), f"{bad} non-compliant resource(s)"


# ---------- Third parties (CTL-014) ----------

@assertion("CTL-014-A1")
def ctl014_a1(ctx):
    rows = ctx.repo_csv("RegisterOfInformation")
    path = ctx.root / ctx.items["RegisterOfInformation"]["target"]
    header = next(csv.reader(path.open(encoding="utf-8")))
    if header != REGISTER_COLUMNS:
        return FAIL, "columns differ from the expected list"
    empty = [f"{r['id']}.{c}" for r in rows for c in REGISTER_MANDATORY if not (r.get(c) or "").strip()]
    return (FAIL, f"empty mandatory values: {names(empty)}") if empty else (PASS, f"{len(rows)} arrangement(s) complete")


@assertion("CTL-014-A2")
def ctl014_a2(ctx):
    bad = []
    for r in ctx.repo_csv("RegisterOfInformation"):
        if r["supports_critical_function"] != "yes" or r["status"] != "active":
            continue
        if not r["exit_plan_ref"] or not (ctx.root / r["exit_plan_ref"]).exists():
            bad.append(f"{r['id']} (exit plan)")
        try:
            age = (ctx.as_of - dt.date.fromisoformat(r["last_assessment"])).days
        except ValueError:
            age = 10**6
        if age > 365:
            bad.append(f"{r['id']} (assessment {r['last_assessment']})")
    return (FAIL, names(bad)) if bad else (PASS, "critical arrangements have exit plan and recent assessment")


# ---------- Governance (CTL-016) ----------

@assertion("CTL-016-A1")
def ctl016_a1(ctx):
    folder = ctx.root / ctx.items["RiskAcceptances"]["target"]
    records = sorted(folder.glob("RA-*.md"))
    if not records:
        raise NoEvidence("RiskAcceptances: no record")
    bad = []
    for f in records:
        text = f.read_text(encoding="utf-8")
        date = re.search(r"^\| Date \| (.*?) \|", text, re.M)
        expiry = re.search(r"^\| Expires \| (.*?) \|", text, re.M)
        try:
            dt.date.fromisoformat(date.group(1).strip() if date else "")
        except ValueError:
            bad.append(f"{f.stem} (date)")
        if not expiry or not expiry.group(1).strip():
            bad.append(f"{f.stem} (expiry)")
    return (FAIL, f"incomplete: {names(bad)}") if bad else (PASS, f"{len(records)} record(s) complete")


# ---------- Cloud posture (CTL-015) ----------

@assertion("CTL-015-A1")
def ctl015_a1(ctx):
    scores = ctx.evidence("SecureScores")
    if not scores:
        raise NoEvidence("SecureScores: empty")
    score = g(scores[0], "properties", "score", default={})
    pct = score.get("percentage")
    if pct is None and score.get("max"):
        pct = score["current"] / score["max"]
    pct = float(pct or 0)
    return (PASS if pct >= SECURE_SCORE_TARGET else FAIL), f"secure score {pct:.0%} (lab target {SECURE_SCORE_TARGET:.0%})"


@assertion("CTL-015-A2")
def ctl015_a2(ctx):
    found = [a for a in ctx.evidence("PolicyAssignments")
             if (a.get("policyDefinitionId") or "").lower().endswith(MCSB_SET_ID)
             or MCSB_NAME in (a.get("displayName") or "").lower()]
    if not found:
        return FAIL, "Microsoft cloud security benchmark initiative not assigned to the subscription"
    enforced = [a for a in found if a.get("enforcementMode", "Default") == "Default"]
    return (PASS if enforced else FAIL), f"{len(found)} benchmark assignment(s), {len(enforced)} enforced"


@assertion("CTL-015-A3")
def ctl015_a3(ctx):
    plans = {p.get("name"): g(p, "properties", "pricingTier") for p in ctx.evidence("DefenderPlans")}
    if not plans:
        raise NoEvidence("DefenderPlans: empty")
    paid = sorted(n for n, tier in plans.items() if tier != "Free")
    if paid:
        return FAIL, f"paid Defender plan(s) on: {names(paid)} (cost guardrail)"
    if "CloudPosture" not in plans:
        return FAIL, "CloudPosture plan not listed: foundational CSPM state unknown"
    return PASS, f"{len(plans)} plan(s), all Free: foundational CSPM only"


@assertion("CTL-015-A4")
def ctl015_a4(ctx):
    std = [s for s in ctx.evidence("RegulatoryComplianceStandards")
           if "security-benchmark" in (s.get("name") or "").lower()]
    if not std:
        return FAIL, "benchmark standard not in regulatory compliance"
    p = std[0].get("properties") or {}
    state = p.get("state")
    detail = (f"{std[0].get('name')}: state {state}, {p.get('passedControls', 0)} passed, "
              f"{p.get('failedControls', 0)} failed, {p.get('skippedControls', 0)} skipped controls")
    return (PASS if state in {"Passed", "Failed"} else FAIL), detail


def unhealthy_recommendations(ctx) -> dict[str, dict]:
    """Recommendation name -> worst severity and earliest first evaluation, over its unhealthy resources."""
    rank = {"Low": 1, "Medium": 2, "High": 3}
    assessments = ctx.evidence("SecurityAssessments")
    if not assessments:
        raise NoEvidence("SecurityAssessments: empty (assessment not run yet?)")
    out: dict[str, dict] = {}
    for a in assessments:
        p = a.get("properties") or {}
        if g(p, "status", "code") != "Unhealthy":
            continue
        name = p.get("displayName") or a.get("name")
        sev = g(p, "metadata", "severity", default="Low")
        first = g(p, "status", "firstEvaluationDate")
        rec = out.setdefault(name, {"severity": sev, "first": first, "resources": 0})
        rec["resources"] += 1
        if rank.get(sev, 0) > rank.get(rec["severity"], 0):
            rec["severity"] = sev
        if first and (not rec["first"] or first < rec["first"]):
            rec["first"] = first
    return out


def remediation_register(ctx) -> dict[str, dict]:
    return {r["recommendation"]: r for r in ctx.repo_csv("RemediationRegister")}


@assertion("CTL-015-A5")
def ctl015_a5(ctx):
    findings = {k: v for k, v in unhealthy_recommendations(ctx).items() if v["severity"] in TRACKED_SEVERITIES}
    register = remediation_register(ctx)
    untracked = [f"{k} ({v['severity']})" for k, v in findings.items() if k not in register]
    if untracked:
        return FAIL, f"unhealthy and not in the remediation register: {names(untracked)}"
    return PASS, f"{len(findings)} High or Medium recommendation(s), all tracked"


@assertion("CTL-015-A6")
def ctl015_a6(ctx):
    findings = unhealthy_recommendations(ctx)
    bad = []
    for name, r in remediation_register(ctx).items():
        f = findings.get(name)
        if r["decision"] == "accept":
            ra = (r.get("risk_acceptance") or "").strip()
            if not ra or not (ctx.root / "risk" / "acceptances" / f"{ra}.md").exists():
                bad.append(f"{r['id']} (accepted without risk acceptance record)")
            continue
        if r["status"] == "closed":
            if f:
                bad.append(f"{r['id']} (closed but still unhealthy on {f['resources']} resource(s))")
            continue
        if f and f["first"]:
            age = (ctx.as_of - parse_ts(f["first"]).date()).days
            sla = REMEDIATION_SLA_DAYS.get(f["severity"], REMEDIATION_SLA_DAYS["Low"])
            if age > sla:
                bad.append(f"{r['id']} ({f['severity']}, open {age} days, SLA {sla})")
    return (FAIL, names(bad)) if bad else (PASS, "no overdue remediation, closures confirmed by the evidence")


# ---------- Engine ----------

def load_controls(root: Path) -> list[dict]:
    return [yaml.safe_load(p.read_text(encoding="utf-8")) for p in sorted((root / "controls" / "sheets").glob("CTL-*.yaml"))]


def control_status(results: list[dict], automation: str) -> str:
    if not results:
        return "MANUAL"
    statuses = {r["status"] for r in results}
    if FAIL in statuses:
        return "NOT_EFFECTIVE"
    if statuses == {PASS}:
        # Effective only when operating effectiveness was machine-tested too.
        return "EFFECTIVE" if any(r["test"] == "effectiveness" for r in results) else "DESIGN_ONLY"
    design = [r for r in results if r["test"] == "design"]
    if design and all(r["status"] == PASS for r in design):
        return "DESIGN_ONLY"
    if statuses == {NO_EVIDENCE}:
        return "NOT_ASSESSED"
    return "PARTIAL"


def evaluate(root: Path, run: Path | None, as_of: dt.date) -> dict:
    ctx = Context(root, run, as_of)
    out = []
    for ctl in load_controls(root):
        results = []
        for a in ctl.get("assertions") or []:
            fn = ASSERTIONS.get(a["id"])
            if fn is None:
                status, detail = NO_EVIDENCE, "assertion not implemented"
            else:
                try:
                    status, detail = fn(ctx)
                except NoEvidence as exc:
                    status, detail = NO_EVIDENCE, str(exc)
            results.append({"id": a["id"], "test": a["test"], "text": a["text"], "status": status, "detail": detail})
        out.append({"id": ctl["id"], "name": ctl["name"], "domain": ctl["domain"], "automation": ctl["automation"],
                    "status": control_status(results, ctl["automation"]), "assertions": results})
    manifest = None
    if run and (run / "manifest.json").exists():
        manifest = json.loads((run / "manifest.json").read_text(encoding="utf-8-sig"))
    return {
        "evaluated_at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%MZ"),
        "as_of": as_of.isoformat(),
        "run_id": manifest.get("run_id") if manifest else None,
        "repo_commit": manifest.get("repo_commit") if manifest else None,
        "controls": out,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--run", type=Path, help="evidence run folder")
    ap.add_argument("--root", type=Path, default=ROOT)
    ap.add_argument("--out", type=Path, help="write results JSON here")
    ap.add_argument("--as-of", type=dt.date.fromisoformat, default=dt.date.today())
    ap.add_argument("--controls", help="comma-separated control IDs to evaluate (default: all)")
    ap.add_argument("--fail-on", choices=["none", "fail"], default="none",
                    help="exit 1 when any assertion FAILs (used in CI for repository-only checks)")
    args = ap.parse_args()
    res = evaluate(args.root.resolve(), args.run.resolve() if args.run else None, args.as_of)
    if args.controls:
        keep = {c.strip() for c in args.controls.split(",")}
        res["controls"] = [c for c in res["controls"] if c["id"] in keep]
    text = json.dumps(res, indent=2)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(text + "\n", encoding="utf-8")
    for c in res["controls"]:
        print(f"{c['id']} {c['status']:<13} {c['name']}")
        for a in c["assertions"]:
            print(f"    {a['id']} {a['status']:<11} {a['detail']}")
    failed = any(a["status"] == FAIL for c in res["controls"] for a in c["assertions"])
    return 1 if (args.fail_on == "fail" and failed) else 0


if __name__ == "__main__":
    sys.exit(main())
