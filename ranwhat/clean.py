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
_SHAPES = [
    re.compile(r"sk_live_[A-Za-z0-9]{12,}"),
    re.compile(r"rk_live_[A-Za-z0-9]{12,}"),
    re.compile(r"sk-[A-Za-z0-9_-]{20,}"),
    re.compile(r"ghp_[A-Za-z0-9]{28,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{40,}"),
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{20,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"AC[0-9a-f]{32}"),                       # Twilio SID
    re.compile(r"SG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),  # JWT
]

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
    return False


def find_secrets(text):
    """Return [(secret_value, label)] found in a blob of text."""
    found = []
    if not text or not _worth_scanning(text):
        return found
    if len(text) > MAX_STRING:
        text = text[:MAX_STRING]

    for pattern in _SHAPES:
        for m in pattern.finditer(text):
            value = m.group(0)
            if not _is_placeholder(value):
                found.append((value, "credential"))

    for m in _ASSIGN.finditer(text):
        key, value = m.group(2), m.group(4)
        if not _SECRET_KEY.search(key):
            continue
        if _is_placeholder(value):
            continue
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


def _walk(node, collect, replace=None):
    """Visit every string in a decoded JSON structure."""
    if isinstance(node, str):
        secrets = find_secrets(node)
        for value, label in secrets:
            collect(value, label)
        if replace and secrets:
            out = node
            for value, _ in secrets:
                out = out.replace(value, REDACTION % _fingerprint(value))
            return out
        return node
    if isinstance(node, list):
        return [_walk(v, collect, replace) for v in node]
    if isinstance(node, dict):
        return {k: _walk(v, collect, replace) for k, v in node.items()}
    return node


def scan_file(path, apply=False):
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
                new = _walk(obj, collect, replace=apply)
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
