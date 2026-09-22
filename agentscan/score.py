"""
Scoring: turns a set of granted credentials plus declared controls into the
three numbers an underwriter actually prices on.

  Authority      how much the agent is allowed to do
  Observability  whether a specific past action can be reconstructed
  Reversibility  whether a wrong action can be undone

Observability is deliberately able to veto the whole result. An agent that
cannot reconstruct its own tool calls for a named incident is not a
well-instrumented agent with a gap -- it is an agent an underwriter cannot
distinguish from the worst case, and prices accordingly.
"""

from __future__ import annotations

from .catalog import (
    lookup, AUTHORITY_RANK, READ, WRITE, FINANCIAL, DESTRUCTIVE,
    MONETARY, EXTERNAL_COMMS, DATA_EGRESS, INFRASTRUCTURE, IDENTITY,
)

# penalty applied per granted scope, by what that scope permits
_AUTHORITY_COST = {READ: 1, WRITE: 6, FINANCIAL: 14, DESTRUCTIVE: 22}

# an unused high-authority scope is a pure least-privilege failure: all of the
# risk, none of the utility. Surcharged rather than merely counted.
_UNUSED_SURCHARGE = 1.5


def _clamp(n, lo=0, hi=100):
    return max(lo, min(hi, n))


def _resolve(credentials):
    """Flatten credentials into resolved scope rows."""
    rows = []
    for cred in credentials:
        provider = cred.get("provider", "generic")
        granted = cred.get("scopes", []) or []
        used = cred.get("scopes_used")
        for scope in granted:
            entry = lookup(provider, scope)
            if used is None:
                usage = "unknown"
            elif scope in used:
                usage = "used"
            else:
                usage = "unused"
            rows.append({
                "provider": provider,
                "credential": cred.get("label", provider),
                "scope": scope,
                "usage": usage,
                **entry,
            })
    return rows


def score_authority(rows):
    penalty = 0.0
    for r in rows:
        cost = _AUTHORITY_COST[r["authority"]]
        if r["usage"] == "unused" and r["authority"] in (FINANCIAL, DESTRUCTIVE, WRITE):
            cost *= _UNUSED_SURCHARGE
        penalty += cost
    return _clamp(int(round(100 - penalty)))


def score_observability(controls):
    days = controls.get("trace_retention_days", 0) or 0
    if days <= 0:
        base = 0
    elif days < 30:
        base = 30
    elif days < 90:
        base = 55
    elif days < 365:
        base = 80
    else:
        base = 95

    # Retention of spans that do not carry tool name, arguments, credential
    # identity and guardrail decision cannot answer "what did it do on Tuesday".
    if not controls.get("tool_call_attributes", False):
        base = min(base, 25)

    if controls.get("tamper_evident", False):
        base = min(100, base + 5)

    return _clamp(int(base))


def score_reversibility(rows, controls):
    actionable = [r for r in rows if r["authority"] != READ]
    if not actionable:
        base = 100.0
    else:
        reversible = sum(1 for r in actionable if r["reversible"])
        base = 100.0 * reversible / len(actionable)

    approval = controls.get("human_approval", "none")
    if approval == "all":
        base += 25
    elif approval == "financial_only":
        base += 12

    if controls.get("spend_cap_usd") is not None:
        base += 8
    if controls.get("kill_switch", False):
        base += 8

    return _clamp(int(round(base)))


def blast_radius(rows, controls):
    dims = {}
    for r in rows:
        if r["authority"] == READ and r["blast"] != DATA_EGRESS:
            continue
        dims.setdefault(r["blast"], []).append(r)

    cap = controls.get("spend_cap_usd")
    monetary = None
    if MONETARY in dims:
        monetary = "unbounded" if cap is None else "$%s per action" % format(cap, ",")

    return {
        "dimensions": sorted(dims.keys()),
        "monetary": monetary,
        "irreversible_actions": sorted(
            {r["scope"] for r in rows if not r["reversible"] and r["authority"] != READ}
        ),
    }


def _grade(n):
    if n >= 85:
        return "A"
    if n >= 70:
        return "B"
    if n >= 55:
        return "C"
    if n >= 40:
        return "D"
    return "F"


def verdict(authority, observability, reversibility):
    """The headline. Observability can veto."""
    if observability < 40:
        return {
            "status": "UNINSURABLE",
            "headline": "Cannot reconstruct past actions",
            "detail": (
                "An underwriter cannot distinguish this deployment from the "
                "worst case, because it cannot produce the tool call, the "
                "authority used, and the guardrail decision for a named past "
                "action. Expect declined coverage or flat-rate penalty pricing "
                "regardless of how well the agent actually behaves."
            ),
        }
    composite = int(round(0.4 * authority + 0.35 * observability + 0.25 * reversibility))
    if composite >= 70:
        status, headline = "INSURABLE", "Priceable risk"
    else:
        status, headline = "IMPAIRED", "Priceable, but expect loaded pricing"
    return {
        "status": status,
        "headline": headline,
        "composite": composite,
        "grade": _grade(composite),
        "detail": "",
    }


def _coverage_findings(profile, rows):
    """Turn usage-pull coverage gaps into explicit findings, so an unverified
    provider never silently reads as a clean one."""
    out = []
    cov = {c["provider"]: c for c in (profile.get("usage_coverage") or [])}
    providers = sorted({r["provider"] for r in rows})

    blind = [p for p in providers
             if p not in cov or cov[p]["level"] == "none"]
    partial = [p for p in providers
               if p in cov and cov[p]["level"] == "writes"]

    if blind:
        out.append({
            "severity": "medium",
            "title": "Usage could not be verified for %d provider(s)" % len(blind),
            "body": "Granted permissions could not be compared against exercised "
                    "ones. Inability to demonstrate least privilege is itself an "
                    "underwriting finding, and these scopes are reported as "
                    "unverified rather than assumed safe.",
            "evidence": blind,
        })
    if partial:
        out.append({
            "severity": "low",
            "title": "Write-only usage coverage",
            "body": "For these providers only mutations are observable, so read "
                    "scopes cannot be confirmed used or unused. Write, financial "
                    "and destructive findings are unaffected.",
            "evidence": partial,
        })
    return out


def findings(rows, controls, ba):
    """Specific, quotable findings. Ordered most severe first."""
    out = []

    unused_high = [r for r in rows
                   if r["usage"] == "unused" and r["authority"] in (FINANCIAL, DESTRUCTIVE)]
    if unused_high:
        out.append({
            "severity": "critical",
            "title": "High-authority permissions granted but never used",
            "body": "%d permission(s) that can move money or destroy data have not "
                    "been exercised in the observed window. This is pure downside: "
                    "full liability, zero utility." % len(unused_high),
            "evidence": [r["scope"] for r in unused_high],
        })

    if not controls.get("tool_call_attributes", False):
        out.append({
            "severity": "critical",
            "title": "Actions are not reconstructable",
            "body": "Traces do not carry tool name, arguments, credential identity "
                    "and guardrail decision. You cannot answer the question an "
                    "underwriter or a plaintiff will ask: what exactly did the "
                    "agent do, and under whose authority.",
            "evidence": [],
        })

    destructive = [r for r in rows if r["authority"] == DESTRUCTIVE]
    if destructive:
        out.append({
            "severity": "critical",
            "title": "Destructive authority held",
            "body": "These permissions allow irreversible destruction of data or "
                    "infrastructure. Several also allow deletion of the records "
                    "that would evidence the action.",
            "evidence": [r["scope"] for r in destructive],
        })

    if ba["monetary"] == "unbounded":
        out.append({
            "severity": "critical",
            "title": "Unbounded financial authority",
            "body": "The agent can move money with no per-action spend cap "
                    "configured.",
            "evidence": [r["scope"] for r in rows if r["authority"] == FINANCIAL],
        })

    if controls.get("human_approval", "none") == "none":
        out.append({
            "severity": "high",
            "title": "No human approval gate",
            "body": "Documented human oversight is becoming a condition of "
                    "coverage, not a best practice. Its absence shifts liability "
                    "squarely onto the operator who configured the agent.",
            "evidence": [],
        })

    if not controls.get("kill_switch", False):
        out.append({
            "severity": "high",
            "title": "No kill switch",
            "body": "There is no documented mechanism to halt the agent mid-task.",
            "evidence": [],
        })

    unknown = [r for r in rows if not r["known"]]
    if unknown:
        out.append({
            "severity": "medium",
            "title": "Unclassified permissions",
            "body": "%d scope(s) are not in the capability catalog and were "
                    "classified by action verb. Confirm these manually." % len(unknown),
            "evidence": [r["scope"] for r in unknown],
        })

    return out


def scan(profile):
    rows = _resolve(profile.get("credentials", []))
    controls = profile.get("controls", {}) or {}

    a = score_authority(rows)
    o = score_observability(controls)
    r = score_reversibility(rows, controls)
    ba = blast_radius(rows, controls)

    return {
        "agent": profile.get("agent", "unnamed-agent"),
        "scores": {"authority": a, "observability": o, "reversibility": r},
        "grades": {"authority": _grade(a), "observability": _grade(o),
                   "reversibility": _grade(r)},
        "verdict": verdict(a, o, r),
        "blast_radius": ba,
        "findings": findings(rows, controls, ba) + _coverage_findings(profile, rows),
        "usage_coverage": profile.get("usage_coverage") or [],
        "scopes": rows,
        "counts": {
            "total": len(rows),
            "used": sum(1 for x in rows if x["usage"] == "used"),
            "unused": sum(1 for x in rows if x["usage"] == "unused"),
            "unknown_usage": sum(1 for x in rows if x["usage"] == "unknown"),
        },
    }
