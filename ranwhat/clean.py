"""
Find secrets sitting in local agent transcripts, and mask them.

When an agent runs `cat .env`, the *output* is written into the transcript --
your database password, your JWT secret, your provider tokens -- in plaintext,
in a file that is never rotated and gets read again by agents later.

Two things this is careful about:

Redaction is not remediation. Masking a value in a transcript does not
un-expose it; it was already written to disk and already sat in a model
context you do not control. The rotation is the fix. Masking only stops it
leaking a second time, and the report says so rather than implying safety.

Never guess. A value is masked only when the surrounding key names it as a
secret, or the value itself carries a recognisable credential shape.
Placeholders are left alone.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import os
import re
import shutil

from .watch import CLAUDE_PROJECTS, discover

BACKUP_ROOT = os.path.expanduser("~/.ranwhat/backups")
REDACTION = "<ranwhat:redacted:%s>"

# Key names that make the value beside them a secret.
_SECRET_KEY = re.compile(
    r"(?:^|[_-])(?:secret|token|password|passwd|pwd|apikey|api_key|"
    r"access_key|private_key|client_secret|auth|credential|dsn|"
    r"session_secret|app_key|signing_key)s?$|"
    r"^(?:database_url|redis_url|mongodb_uri|postgres_url|db_password)$",
    re.I)

# Credential shapes that are secrets wherever they appear.
# Each shape is named, because "credential" tells you nothing about where to
# go and roll it.
_SHAPES_NAMED = [
    (re.compile(r"sk_live_[A-Za-z0-9]{12,}"), "Stripe live secret key"),
    (re.compile(r"rk_live_[A-Za-z0-9]{12,}"), "Stripe restricted key"),
    (re.compile(r"sk-[A-Za-z0-9_-]{20,}"), "OpenAI/Anthropic-style API key"),
    (re.compile(r"ghp_[A-Za-z0-9]{28,}"), "GitHub personal access token"),
    (re.compile(r"github_pat_[A-Za-z0-9_]{40,}"), "GitHub fine-grained token"),
    (re.compile(r"xox[baprs]-[A-Za-z0-9-]{20,}"), "Slack token"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS access key ID"),
    (re.compile(r"ASIA[0-9A-Z]{16}"), "AWS temporary access key"),
    (re.compile(r"AC[0-9a-f]{32}"), "Twilio account SID"),
    (re.compile(r"SG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}"), "SendGrid API key"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z ]*PRIVATE KEY-----"),
     "private key"),
    (re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
     "JSON Web Token"),
]

_SHAPES = [pattern for pattern, _name in _SHAPES_NAMED]

# KEY=value / "key": "value" assignments.
_ASSIGN = re.compile(
    r"""(["']?)([A-Za-z_][A-Za-z0-9_]*)\1\s*[:=]\s*(["']?)([^\s"',;}\)]{8,})\3""")

# A password embedded in a connection string.
_CONN = re.compile(r"(?P<pre>[a-z][a-z0-9+.-]*://[^:/\s]+:)(?P<secret>[^@\s/]{4,})(?P<post>@)")

# Values that are deliberately not real.
_PLACEHOLDER = re.compile(
    r"^(?:<[^>]*>|\{\{.*\}\}|\$\{?[A-Z_]+\}?|x{3,}|\*{3,}|\.{3,}|-+|"
    r"(?:changeme|change[-_]me|your|placeholder|example|sample|test|dummy|"
    r"insert|replace|enter|add)[-_ ]?[\w-]*|"
    r"none|null|true|false|undefined|redacted|secret|password|todo|fixme|"
    r"ranwhat:redacted:[0-9a-f]+)$",
    re.I)


# A string can only hold a secret if it has an assignment, a connection
# string, or a known credential prefix. Most of a transcript is prose, and
# checking this first skips the regex battery on the overwhelming majority.
_CHEAP = ("=", ":", "sk_", "rk_", "sk-", "ghp_", "github_pat_", "xox",
          "AKIA", "AC", "SG.", "eyJ", "BEGIN")

# A single string longer than this is a data blob -- a build log, a base64
# payload, a file dump. Secrets in the first megabyte are still found.
MAX_STRING = 1_000_000


def _worth_scanning(text):
    return any(token in text for token in _CHEAP)


def _fingerprint(value):
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:12]


# A secret is a literal. These are all things that merely *refer* to one, or
# compute one, or describe one -- and on a working machine they outnumbered
# real credentials roughly two to one.
_CODE = re.compile(r"[(){}\[\]`<>|\\]|=>|\$\{|\$\(")
_REFERENCE = re.compile(
    r"^(?:process\.env|os\.environ|import\.meta|this\.|self\.|window\.|"
    r"globalThis\.|config\.|env\.|Deno\.env|ENV\[)", re.I)
_PATHLIKE = re.compile(r"^(?:[~.]?/|[A-Za-z]:\\)")
_REGEXISH = re.compile(r"\.\*|\\[dwsb]|\{\d+(?:,\d*)?\}|\[[A-Za-z0-9-]+\]")
_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_MASKED = re.compile(r"\*{3,}|x{6,}|\u2026|_{6,}")


def _entropy(value):
    """Shannon entropy per character. Generated credentials sit well above
    three bits; words, names and code sit below."""
    if not value:
        return 0.0
    import math
    counts = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    n = float(len(value))
    return -sum((c / n) * math.log(c / n, 2) for c in counts.values())


def _looks_computed(value):
    """True when the value is code, a reference, a path or a pattern rather
    than a literal credential."""
    v = value.strip().strip("\"'")
    if _CODE.search(v) or _REFERENCE.match(v) or _PATHLIKE.match(v):
        return True
    if _REGEXISH.search(v) or _MASKED.search(v):
        return True
    # A bare identifier with no digits is a variable name, not a secret.
    if _IDENTIFIER.match(v) and not any(c.isdigit() for c in v) and len(v) < 40:
        return True
    return False


def _is_placeholder(value):
    v = value.strip().strip("\"'")
    if len(v) < 8:
        return True
    if _PLACEHOLDER.match(v):
        return True
    if v.startswith("<ranwhat:redacted:"):
        return True
    if len(set(v)) <= 2:                      # aaaaaaaa, ********
        return True
    if _looks_computed(v):
        return True
    return False


def find_secrets(text):
    """Return [(secret_value, label)] found in a blob of text."""
    found = []
    if not text or not _worth_scanning(text):
        return found
    if len(text) > MAX_STRING:
        text = text[:MAX_STRING]

    for pattern, name in _SHAPES_NAMED:
        for m in pattern.finditer(text):
            value = m.group(0)
            if not _is_placeholder(value):
                found.append((value, name))

    for m in _ASSIGN.finditer(text):
        key, value = m.group(2), m.group(4)
        if not _SECRET_KEY.search(key):
            continue
        if _is_placeholder(value):
            continue
        if _entropy(value) < 3.0 and not any(p.search(value) for p in _SHAPES):
            continue          # prose or a word, not a generated credential
        found.append((value, key))

    for m in _CONN.finditer(text):
        value = m.group("secret")
        if not _is_placeholder(value):
            found.append((value, "connection string password"))

    # Longest first, so a JWT is masked before any substring of it -- and a
    # password that lives inside an already-matched connection string is not
    # reported a second time on its own.
    seen, unique = set(), []
    for value, label in sorted(found, key=lambda p: len(p[0]), reverse=True):
        if value in seen:
            continue
        if any(value in bigger for bigger in seen):
            continue
        seen.add(value)
        unique.append((value, label))
    return unique


def _walk(node, collect, replace=None, only=None):
    """Visit every string in a decoded JSON structure.

    `only` limits masking to a set of fingerprints, so acting on one finding
    does not rewrite every other secret in the same file.
    """
    if isinstance(node, str):
        secrets = find_secrets(node)
        for value, label in secrets:
            collect(value, label)
        if replace and secrets:
            out = node
            for value, _ in secrets:
                if only is not None and _fingerprint(value) not in only:
                    continue
                out = out.replace(value, REDACTION % _fingerprint(value))
            return out
        return node
    if isinstance(node, list):
        return [_walk(v, collect, replace, only) for v in node]
    if isinstance(node, dict):
        return {k: _walk(v, collect, replace, only) for k, v in node.items()}
    return node


def scan_file(path, apply=False, only=None):
    """Find (and optionally mask) secrets in one transcript.

    Returns (findings, changed). Each finding is a dict describing one
    distinct secret value and where it was seen.
    """
    findings = {}
    rewritten = []
    changed = False

    def collect(value, label):
        entry = findings.setdefault(_fingerprint(value), {
            "fingerprint": _fingerprint(value),
            "label": label,
            "length": len(value),
            "hint": value[:3] + "…" + value[-2:] if len(value) > 10 else "…",
            "files": set(),
            "count": 0,
        })
        entry["files"].add(path)
        entry["count"] += 1

    try:
        with open(path, "r", errors="replace") as fh:
            for line in fh:
                stripped = line.strip()
                if not stripped:
                    rewritten.append(line)
                    continue
                try:
                    obj = json.loads(stripped)
                except ValueError:
                    rewritten.append(line)
                    continue
                new = _walk(obj, collect, replace=apply, only=only)
                if apply and new != obj:
                    changed = True
                    rewritten.append(json.dumps(new, ensure_ascii=False) + "\n")
                else:
                    rewritten.append(line)
    except OSError:
        return {}, False

    if apply and changed:
        _backup(path)
        tmp = path + ".ranwhat-tmp"
        with open(tmp, "w") as fh:
            fh.writelines(rewritten)
        # refuse to install a file we cannot read back
        with open(tmp) as fh:
            for line in fh:
                if line.strip():
                    json.loads(line)
        os.replace(tmp, path)

    return findings, changed


def _backup(path):
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    dest = os.path.join(BACKUP_ROOT, stamp, path.lstrip("/"))
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    shutil.copy2(path, dest)
    return dest


def scan(root=CLAUDE_PROJECTS, since_days=None, apply=False, progress=None):
    """Scan every transcript. Returns (merged_findings, files_scanned, files_changed).

    `progress` is called with (index, total, path) before each file. A large
    history takes a couple of minutes, and a run that prints nothing for that
    long is indistinguishable from one that has hung.
    """
    merged, scanned, changed_files = {}, 0, []
    paths = discover(root, since_days)
    for index, path in enumerate(paths, 1):
        if progress:
            progress(index, len(paths), path)
        scanned += 1
        findings, changed = scan_file(path, apply=apply)
        if changed:
            changed_files.append(path)
        for fp, entry in findings.items():
            if fp in merged:
                merged[fp]["files"] |= entry["files"]
                merged[fp]["count"] += entry["count"]
            else:
                merged[fp] = entry
    return merged, scanned, changed_files


def render(findings, scanned, changed_files, applied):
    from .report import BOLD, DIM, RED, YEL, GRN, CYA

    L = ["", BOLD("  ranwhat clean  ") + DIM("· secrets sitting in local transcripts"),
         DIM("  " + "-" * 62),
         "  %d transcript(s) scanned" % scanned, ""]

    if not findings:
        L += ["  " + GRN("No secrets found."), ""]
        return "\n".join(L)

    total = sum(f["count"] for f in findings.values())
    L.append("  " + RED(BOLD("%d distinct secret(s)" % len(findings)))
             + DIM(" in %d place(s)" % total))
    L.append("")
    L.append("  " + BOLD("These must be rotated."))
    for line in ("They have been written to disk in plaintext and sat in a model",
                 "context you do not control. Masking them here stops them leaking",
                 "again. It does not make them safe."):
        L.append(DIM("  " + line))
    L.append("")

    for f in sorted(findings.values(), key=lambda x: -x["count"]):
        where = sorted(f["files"])
        L.append("  " + RED("* ") + BOLD(f["label"])
                 + DIM("   %s  %d chars  seen %dx" % (f["hint"], f["length"], f["count"])))
        for path in where[:3]:
            L.append(DIM("      %s" % os.path.basename(os.path.dirname(path))))
        if len(where) > 3:
            L.append(DIM("      … and %d more transcript(s)" % (len(where) - 3)))
    L.append("")

    if applied:
        L.append("  " + GRN("Masked in %d file(s)." % len(changed_files)))
        L.append(DIM("  Backups: %s" % BACKUP_ROOT))
    else:
        L.append("  " + YEL("Dry run. Nothing was changed."))
        L.append(DIM("  Run with --apply to mask them. Backups are written first."))
    L += ["", DIM("  " + "-" * 62),
          DIM("  Read locally. Nothing was transmitted."), ""]
    return "\n".join(L)


# ---------------------------------------------------------------------------
# Interactive review.
#
# Scanning a real history takes a while, and the findings are already in
# memory when the report prints. Making the user re-run the whole command to
# act on what they just read wastes that, so the session stays open.
# ---------------------------------------------------------------------------

HELP = """  commands
    list                  show the findings again
    show <n>              where that secret appears, and what it looks like
    mask <n>              mask just that one
    mask all              mask everything listed
    keep <n>              leave it alone, drop it from the list
    rotate                what to rotate, grouped by provider
    quit                  leave (nothing is masked unless you asked)
"""

# Which provider a key name points at, for the rotation checklist.
_PROVIDER = [
    (re.compile(r"aws|akia|asia", re.I), "AWS — IAM console, deactivate then delete the old key"),
    (re.compile(r"openai|anthropic", re.I), "OpenAI / Anthropic — dashboard > API keys > revoke"),
    (re.compile(r"slack", re.I), "Slack — api.slack.com > your app > reinstall"),
    (re.compile(r"sendgrid", re.I), "SendGrid — Settings > API keys"),
    (re.compile(r"json web token|jwt", re.I),
     "JWT — signed by your own secret; rotate the signing secret"),
    (re.compile(r"private key", re.I), "Private key — regenerate the pair and redeploy the public half"),
    (re.compile(r"stripe|sk_live|rk_live", re.I), "Stripe — Developers > API keys > roll"),
    (re.compile(r"twilio|^ac[0-9a-f]{32}", re.I), "Twilio — Console > Account > API keys"),
    (re.compile(r"meta|facebook|pusher", re.I), "Meta / Pusher — app dashboard > regenerate"),
    (re.compile(r"github|ghp_|gho_", re.I), "GitHub — Settings > Developer settings > tokens"),
    (re.compile(r"render", re.I), "Render — Account settings > API keys"),
    (re.compile(r"turnstile|cloudflare", re.I), "Cloudflare — dashboard > the relevant service"),
    (re.compile(r"telegram", re.I), "Telegram — BotFather > /revoke"),
    (re.compile(r"database_url|postgres|redis|db_password|mongo", re.I),
     "Database — change the password, then update every consumer"),
    (re.compile(r"jwt|session|cron|app_key|signing", re.I),
     "Application secret — you generate this one; rotating invalidates sessions"),
]


def _provider_for(label):
    for pattern, advice in _PROVIDER:
        if pattern.search(label):
            return advice
    return "Unknown — find where this key lives and roll it there"


def _numbered(findings):
    return sorted(findings.values(), key=lambda x: -x["count"])


def review(findings, scanned, stream=None):
    """Interactive review of an already-completed scan. Returns the number of
    files changed."""
    import sys as _sys
    from .report import BOLD, DIM, RED, GRN, YEL

    out = stream or _sys.stdout
    items = _numbered(findings)
    changed_total = 0

    def _print(text=""):
        out.write(text + "\n")

    _print(DIM("  %d finding(s). Type 'help' for commands." % len(items)))
    _print()

    while True:
        try:
            raw = input("  ranwhat> ").strip()
        except (EOFError, KeyboardInterrupt):
            _print()
            return changed_total
        if not raw:
            continue

        parts = raw.split()
        cmd, arg = parts[0].lower(), (parts[1] if len(parts) > 1 else None)

        if cmd in ("quit", "exit", "q"):
            return changed_total

        if cmd in ("help", "?"):
            _print(HELP)
            continue

        if cmd == "list":
            for i, f in enumerate(items, 1):
                _print("  %s %-24s %s %d chars, seen %dx"
                       % (BOLD("%3d" % i), f["label"], DIM(f["hint"]),
                          f["length"], f["count"]))
            _print()
            continue

        if cmd == "rotate":
            groups = {}
            for f in items:
                groups.setdefault(_provider_for(f["label"]), []).append(f)
            for advice, group in sorted(groups.items()):
                _print("  " + BOLD(advice))
                for f in group:
                    _print(DIM("      %-24s seen %dx" % (f["label"], f["count"])))
                _print()
            continue

        if cmd in ("show", "mask", "keep"):
            if cmd == "mask" and arg == "all":
                changed_total += _mask(items, scanned, _print, GRN, RED)
                items = []
                continue
            if not arg or not arg.isdigit() or not (1 <= int(arg) <= len(items)):
                _print(RED("  need a number from 1 to %d" % len(items)))
                continue
            target = items[int(arg) - 1]

            if cmd == "show":
                _print("  " + BOLD(target["label"]))
                _print(DIM("      looks like : %s" % target["hint"]))
                _print(DIM("      length     : %d characters" % target["length"]))
                _print(DIM("      occurrences: %d" % target["count"]))
                _print(DIM("      rotate at  : %s" % _provider_for(target["label"])))
                for path in sorted(target["files"]):
                    _print(DIM("      %s" % path))
                _print()
            elif cmd == "keep":
                items.remove(target)
                _print(DIM("  kept. %d left." % len(items)))
            else:
                changed_total += _mask([target], scanned, _print, GRN, RED)
                items.remove(target)
            continue

        _print(RED("  unknown command: %s" % cmd) + DIM("  (try 'help')"))


def _mask(targets, scanned, _print, GRN, RED):
    """Re-walk only the files that hold these secrets, masking just them."""
    wanted = {t["fingerprint"] for t in targets}
    paths = set()
    for t in targets:
        paths |= set(t["files"])

    changed = 0
    for path in sorted(paths):
        found, did = scan_file(path, apply=True, only=wanted)
        if did:
            changed += 1
    if changed:
        _print(GRN("  masked in %d file(s)." % changed)
               + (" Backups: %s" % BACKUP_ROOT))
    else:
        _print(RED("  nothing changed."))
    return changed
