"""
Local agent watch: a flight recorder for agents running on this machine.

Not antivirus. There is no adversary and no signature -- you asked the agent
to do things. So this does not try to decide whether an action was permitted.
It records what happened and raises a narrow set of actions you would want to
know about regardless of intent.

Precision over recall, deliberately. A watcher that fires on every file write
gets muted in a day, and a muted watcher records nothing anyone reads.

Sources are pluggable. Claude Code writes JSONL session transcripts locally,
which makes it the source that can be validated against real data today; an
OTLP receiver slots in behind the same Action Record interface.
"""

from __future__ import annotations

import glob
import shlex
import hashlib
import json
import os
import re
import time

CLAUDE_PROJECTS = os.path.expanduser("~/.claude/projects")

CRITICAL, HIGH, MEDIUM = "critical", "high", "medium"


class Rule(object):
    def __init__(self, rid, severity, title, why, patterns, suppress_on_search=True):
        self.id = rid
        self.severity = severity
        self.title = title
        self.why = why
        self.patterns = [re.compile(p, re.I) for p in patterns]
        # Searching FOR a dangerous string is not doing the dangerous thing.
        # `grep -r "rm -rf"` and `grep .aws/credentials` must not fire.
        self.suppress_on_search = suppress_on_search

    def match(self, text):
        for p in self.patterns:
            m = p.search(text)
            if m:
                return m
        return None


_SEARCH_CMD = re.compile(
    r"^\s*(?:sudo\s+)?(?:grep|egrep|fgrep|rg|ripgrep|ag|ack|find|locate|mdfind)\b")
_SEARCH_ACTS = re.compile(r"-delete\b|-exec\b|-ok\b|\|\s*xargs\b")


def _is_search(command):
    """True when the command only looks for text, rather than acting on it."""
    if not command:
        return False
    for part in re.split(r"(?:\|\||&&|;|\|)", command):
        if _SEARCH_CMD.match(part) and not _SEARCH_ACTS.search(part):
            continue
        if part.strip():
            return False
    return True


def _context(text, match, width=70):
    """Evidence a human can judge. 'rm -rf' alone tells you nothing; you need
    to see what it was pointed at."""
    start = max(0, match.start() - 20)
    end = min(len(text), match.end() + width)
    snippet = text[start:end].replace("\n", " ").strip()
    return ("…" if start > 0 else "") + snippet + ("…" if end < len(text) else "")


RULES = [
    Rule("cred.read", CRITICAL,
         "Credential material accessed",
         "The agent read a file whose only purpose is to hold secrets. Whatever "
         "it read is now in a model context you do not control.",
         [r"(?:^|[\s\"'=/])\.env(?:\.[\w-]+)?\b",
          r"\.aws/credentials", r"\.ssh/id_[\w]+", r"\.netrc",
          r"\.config/gcloud", r"service[-_]account.*\.json",
          r"security\s+find-generic-password", r"\.kube/config"]),

    Rule("secret.literal", CRITICAL,
         "Secret-shaped string in a command",
         "A live credential appeared verbatim in a command. Even if the command "
         "was benign, the value is now in shell history and the transcript.",
         [r"sk_live_[A-Za-z0-9]{8,}", r"rk_live_[A-Za-z0-9]{8,}",
          r"ghp_[A-Za-z0-9]{20,}", r"github_pat_[A-Za-z0-9_]{20,}",
          r"xox[baprs]-[A-Za-z0-9-]{10,}", r"AKIA[0-9A-Z]{16}",
          r"-----BEGIN [A-Z ]*PRIVATE KEY-----"], suppress_on_search=False),

    Rule("git.destructive", HIGH,
         "Destructive git operation",
         "History rewriting or branch deletion. This is the class of action "
         "that destroys the record of what else happened.",
         [r"git\s+push\b[^|;&]*--force(?!-with-lease)",
          r"git\s+push\b[^|;&]*\s-f\b",
          r"git\s+reset\s+--hard",
          r"git\s+branch\s+-D\b",
          r"git\s+clean\s+-[a-z]*f",
          r"git\s+filter-branch", r"git\s+remote\s+remove"]),

    Rule("publish", CRITICAL,
         "Package or release published",
         "Something was pushed to a registry other people install from. "
         "Supply-chain reach, and usually irreversible.",
         [r"npm\s+publish", r"yarn\s+publish", r"pnpm\s+publish",
          r"twine\s+upload", r"cargo\s+publish", r"gem\s+push",
          r"gh\s+release\s+create", r"docker\s+push"]),

    Rule("fs.destructive", HIGH,
         "Bulk or recursive deletion",
         "Recursive deletion. Recoverable only if something else was backing "
         "it up.",
         [r"rm\s+-[a-z]*r[a-z]*f", r"rm\s+-[a-z]*f[a-z]*r",
          r"find\s+[^|;&]*-delete\b",
          r"git\s+rm\s+-r", r"shred\s+", r"truncate\s+-s\s*0"]),

    Rule("cloud.destructive", CRITICAL,
         "Cloud resource destroyed or modified",
         "A write or delete against live cloud infrastructure.",
         [r"aws\s+[\w-]+\s+delete-[\w-]+", r"aws\s+[\w-]+\s+terminate-[\w-]+",
          r"aws\s+s3\s+rm\b", r"aws\s+iam\s+(?:put|attach|create)-[\w-]+",
          r"kubectl\s+delete", r"gcloud\s+[\w-]+\s+delete",
          r"terraform\s+(?:destroy|apply\s+-auto-approve)",
          r"drop\s+(?:table|database)\s"]),

    Rule("money", CRITICAL,
         "Financial API called",
         "A call against a payments API. Every one of these moves real money.",
         [r"api\.stripe\.com/v1/(?:charges|refunds|transfers|payouts)",
          r"api\.paypal\.com", r"\bstripe\s+(?:charges|refunds|payouts)\s+create"]),

    Rule("audit.tamper", CRITICAL,
         "Log or history tampering",
         "An action whose effect is to remove the record of other actions.",
         [r"history\s+-c", r">\s*~?/?\.(?:bash|zsh)_history",
          r"rm\s+[^|;&]*\.(?:bash|zsh)_history",
          r"aws\s+cloudtrail\s+(?:delete|stop)-", r"rm\s+-rf?\s+[^|;&]*\.git\b"]),

    Rule("exfil.shape", HIGH,
         "Local file piped to the network",
         "File contents sent outbound in a single command. This is the shape of "
         "exfiltration whether or not that was the intent.",
         [r"(?:cat|tar|zip|base64)\s+[^|;&]+\|\s*(?:curl|wget|nc)\b",
          r"curl\s+[^|;&]*(?:--data-binary|-d)\s*@",
          r"curl\s+[^|;&]*-F\s+[\"']?file=@"]),
]


# Keys whose values are file CONTENT being written, not commands being run.
# An agent writing a script that contains "rm -rf" has not deleted anything;
# running it is a separate tool call that this watcher will see on its own.
_CONTENT_KEYS = {"content", "new_string", "old_string", "body", "text",
                 "file_text", "patch", "diff", "prompt"}

_HEREDOC = re.compile(
    r"<<-?\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1.*?^\2\s*$",
    re.S | re.M)


def _strip_heredocs(command):
    """Remove heredoc bodies. The body is data being written to disk, not a
    sequence of commands being executed."""
    if not command or "<<" not in command:
        return command
    return _HEREDOC.sub("<<REDACTED_HEREDOC", command)


# Interpreters whose -c/-e payload is source in ANOTHER language. "rm -rf"
# inside a Python string is a string, not a deletion. Shell interpreters are
# the exception: their payload really is shell, so we recurse into it.
_FOREIGN_INTERPRETERS = {"python", "python2", "python3", "node", "nodejs",
                         "perl", "ruby", "php", "osascript", "awk", "jq"}
_SHELL_INTERPRETERS = {"sh", "bash", "zsh", "dash", "ksh"}
_PAYLOAD_FLAGS = {"-c", "-e", "--eval", "--command"}

_SPLIT_OPS = re.compile(r"\s*(?:\|\||&&|;|\||\n)\s*")

# Fallback for when the payload contains quoting that shlex cannot parse --
# which is common, because the payload is source code in another language.
# Truncating at the flag is always safe: nothing after it is shell.
_FOREIGN_PAYLOAD = re.compile(
    r"^\s*(?:sudo\s+)?(?:%s)\b[^|;&]*?\s(-c|-e|--eval)\s"
    % "|".join(sorted(_FOREIGN_INTERPRETERS)))


_FOREIGN_OPEN = re.compile(
    r"(?:^|[\s;&|])(?:sudo\s+)?(?:%s)\s+(?:-[A-Za-z]+\s+)*(?:-c|-e|--eval)\s+(['\"])"
    % "|".join(sorted(_FOREIGN_INTERPRETERS)))


def _neutralize_foreign_payloads(command):
    """Blank out the source payload of a non-shell interpreter.

    Must run on the whole command before splitting on shell operators,
    because the payload frequently contains ';' and '|' of its own and
    splitting first tears it into fragments that no longer look like an
    interpreter call.
    """
    out, pos = [], 0
    while True:
        m = _FOREIGN_OPEN.search(command, pos)
        if not m:
            out.append(command[pos:])
            break
        quote = m.group(1)
        i = m.end()
        while i < len(command):
            if command[i] == "\\":
                i += 2
                continue
            if command[i] == quote:
                break
            i += 1
        out.append(command[pos:m.end()])
        out.append("FOREIGN_SOURCE")
        pos = min(i + 1, len(command))
    return "".join(out)


def _executable_text(command, depth=0):
    """Reduce a shell command to only the parts that are actually executed.

    Drops heredoc bodies and the source payloads of foreign interpreters,
    recursing into shell interpreters. This is what stops a script that
    *contains* a dangerous string from reading as a dangerous action.
    """
    if not command or depth > 3:
        return command or ""
    command = _strip_heredocs(command)
    command = _neutralize_foreign_payloads(command)

    kept = []
    for segment in _SPLIT_OPS.split(command):
        segment = segment.strip()
        if not segment:
            continue
        foreign = _FOREIGN_PAYLOAD.match(segment)
        if foreign:
            kept.append(segment[:foreign.end()])
            continue

        try:
            argv = shlex.split(segment)
        except ValueError:
            kept.append(segment)          # unbalanced quotes: keep it all
            continue
        if not argv:
            continue

        binary = os.path.basename(argv[0]).split("/")[-1]
        payload_idx = next((i for i, a in enumerate(argv) if a in _PAYLOAD_FLAGS), None)

        if binary in _FOREIGN_INTERPRETERS and payload_idx is not None:
            kept.append(" ".join(argv[:payload_idx + 1]))
            continue
        if binary in _SHELL_INTERPRETERS and payload_idx is not None:
            head = " ".join(argv[:payload_idx + 1])
            body = argv[payload_idx + 1] if payload_idx + 1 < len(argv) else ""
            kept.append(head + " " + _executable_text(body, depth + 1))
            continue
        kept.append(segment)

    return " ; ".join(kept)


def _flatten(obj, depth=0):
    """Collapse a tool input into searchable text."""
    if depth > 6:
        return ""
    if isinstance(obj, str):
        return obj
    if isinstance(obj, (int, float, bool)) or obj is None:
        return str(obj)
    if isinstance(obj, list):
        return " ".join(_flatten(o, depth + 1) for o in obj)
    if isinstance(obj, dict):
        parts = []
        for k, v in obj.items():
            if k in _CONTENT_KEYS:
                continue
            if k == "command" and isinstance(v, str):
                v = _executable_text(v)
            parts.append("%s %s" % (k, _flatten(v, depth + 1)))
        return " ".join(parts)
    return ""


def _hash(text):
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:16]


def evaluate(tool_name, tool_input):
    """Return the rules a single tool call trips."""
    text = _flatten(tool_input)
    command = tool_input.get("command") if isinstance(tool_input, dict) else None
    command = _executable_text(command) if command else command
    searching = _is_search(command)

    hits = []
    for rule in RULES:
        if searching and rule.suppress_on_search:
            continue
        m = rule.match(text)
        if m:
            hits.append({"rule": rule.id, "severity": rule.severity,
                         "title": rule.title, "why": rule.why,
                         "evidence": _context(text, m)})
    return hits, text


# --------------------------------------------------------------------------
# Source: Claude Code JSONL transcripts
# --------------------------------------------------------------------------

def _iter_claude_tool_calls(path):
    try:
        fh = open(path, "r", errors="replace")
    except OSError:
        return
    with fh:
        for line in fh:
            try:
                entry = json.loads(line)
            except ValueError:
                continue
            msg = entry.get("message")
            if not isinstance(msg, dict):
                continue
            content = msg.get("content")
            if not isinstance(content, list):
                continue
            for block in content:
                if isinstance(block, dict) and block.get("type") == "tool_use":
                    yield entry, block


def scan_transcript(path, source="claude-code"):
    """Produce Action Records for one transcript."""
    records = []
    session = os.path.splitext(os.path.basename(path))[0]
    project = os.path.basename(os.path.dirname(path))

    for entry, block in _iter_claude_tool_calls(path):
        tool = block.get("name", "?")
        tool_input = block.get("input", {})
        hits, text = evaluate(tool, tool_input)
        if not hits:
            continue
        records.append({
            "source": source,
            "session": session,
            "project": project,
            "timestamp": entry.get("timestamp"),
            "tool_name": tool,
            "tool_call_id": block.get("id"),
            "payload_hash": _hash(text),
            "severity": max(hits, key=lambda h: ["medium", "high", "critical"]
                            .index(h["severity"]))["severity"],
            "hits": hits,
        })
    return records


def discover(root=CLAUDE_PROJECTS, since_days=None):
    paths = sorted(glob.glob(os.path.join(root, "*", "*.jsonl")),
                   key=lambda p: os.path.getmtime(p), reverse=True)
    if since_days:
        cutoff = time.time() - since_days * 86400
        paths = [p for p in paths if os.path.getmtime(p) >= cutoff]
    return paths


def scan_all(root=CLAUDE_PROJECTS, since_days=None, limit=None):
    records, scanned = [], 0
    for path in discover(root, since_days):
        if limit and scanned >= limit:
            break
        records.extend(scan_transcript(path))
        scanned += 1
    records.sort(key=lambda r: r.get("timestamp") or "", reverse=True)
    return records, scanned


def render(records, scanned, days):
    from .report import BOLD, DIM, RED, YEL, CYA, GRN
    colour = {CRITICAL: RED, HIGH: YEL, MEDIUM: CYA}
    L = ["", BOLD("  agentscan watch  ") + DIM("· local agent flight recorder"),
         DIM("  " + "-" * 62),
         "  %d transcript(s) over %d days" % (scanned, days), ""]
    if not records:
        L += ["  " + GRN("Nothing flagged."),
              DIM("  Every tool call was read, none tripped a rule."), ""]
        return "\n".join(L)

    counts = {}
    for r in records:
        counts[r["severity"]] = counts.get(r["severity"], 0) + 1
    L.append("  " + "  ".join(colour[k](BOLD("%d %s" % (v, k)))
                              for k, v in sorted(counts.items())))
    L.append("")
    for r in records:
        when = (r.get("timestamp") or "")[:19].replace("T", " ")
        L.append("  " + colour[r["severity"]]("* ") + BOLD(r["hits"][0]["title"])
                 + DIM("   %s  %s" % (when, r["tool_name"])))
        for h in r["hits"]:
            L.append(DIM("      %s" % h["evidence"][:96]))
        L.append(DIM("      -> %s" % r["hits"][0]["why"][:92]))
        L.append("")
    L += [DIM("  " + "-" * 62),
          DIM("  Read locally. Nothing was transmitted."), ""]
    return "\n".join(L)
