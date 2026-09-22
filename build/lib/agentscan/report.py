"""Terminal rendering."""
from __future__ import annotations
import sys

def _c(code, s):
    if not sys.stdout.isatty():
        return s
    return "\033[%sm%s\033[0m" % (code, s)

BOLD = lambda s: _c("1", s)
DIM = lambda s: _c("2", s)
RED = lambda s: _c("31", s)
YEL = lambda s: _c("33", s)
GRN = lambda s: _c("32", s)
CYA = lambda s: _c("36", s)

SEV_COLOR = {"critical": RED, "high": YEL, "medium": CYA, "low": DIM}


def _bar(n, width=24):
    filled = int(round(width * n / 100.0))
    colour = RED if n < 40 else (YEL if n < 70 else GRN)
    return colour("█" * filled) + DIM("░" * (width - filled))


def render(result):
    L = []
    L.append("")
    L.append(BOLD("  agentscan  ") + DIM("· agent authority & insurability"))
    L.append(DIM("  " + "─" * 62))
    L.append("  agent: " + BOLD(result["agent"]))
    L.append("")

    v = result["verdict"]
    badge = {"UNINSURABLE": RED, "IMPAIRED": YEL, "INSURABLE": GRN}[v["status"]]
    L.append("  " + badge(BOLD(" %s " % v["status"])) + "  " + BOLD(v["headline"]))
    if v.get("composite") is not None:
        L.append("  composite %s/100  grade %s" % (v["composite"], v["grade"]))
    if v["detail"]:
        body = v["detail"]
        line = "  "
        for word in body.split():
            if len(line) + len(word) > 70:
                L.append(DIM(line)); line = "  "
            line += word + " "
        L.append(DIM(line))
    L.append("")

    for key, label in (("authority", "Authority    "),
                       ("observability", "Observability"),
                       ("reversibility", "Reversibility")):
        n = result["scores"][key]
        L.append("  %s  %s  %3d  %s" % (label, _bar(n), n, result["grades"][key]))
    L.append("")

    c = result["counts"]
    L.append("  " + BOLD("Permissions"))
    L.append("    %d granted · %s used · %s never used"
             % (c["total"], c["used"], RED(str(c["unused"])) if c["unused"] else "0"))
    ba = result["blast_radius"]
    if ba["monetary"]:
        L.append("    financial authority: " + RED(ba["monetary"]))
    L.append("    blast radius: " + ", ".join(ba["dimensions"]))
    L.append("    irreversible actions: %d" % len(ba["irreversible_actions"]))
    L.append("")

    L.append("  " + BOLD("Findings"))
    for f in result["findings"]:
        colour = SEV_COLOR.get(f["severity"], DIM)
        L.append("    " + colour("● ") + BOLD(f["title"]))
        line = "      "
        for word in f["body"].split():
            if len(line) + len(word) > 72:
                L.append(DIM(line)); line = "      "
            line += word + " "
        L.append(DIM(line))
        for ev in f["evidence"][:6]:
            L.append(DIM("        · " + ev))
        if len(f["evidence"]) > 6:
            L.append(DIM("        · … and %d more" % (len(f["evidence"]) - 6)))
        L.append("")

    unused = [r for r in result["scopes"] if r["usage"] == "unused"]
    if unused:
        L.append("  " + BOLD("Granted but never exercised"))
        for r in sorted(unused, key=lambda x: x["authority"], reverse=True)[:10]:
            L.append("    %-14s %s" % (r["provider"], r["scope"]))
            L.append(DIM("                   %s" % r["label"]))
        L.append("")

    L.append(DIM("  " + "─" * 62))
    L.append(DIM("  No credential, prompt or payload left this machine."))
    L.append("")
    return "\n".join(L)
