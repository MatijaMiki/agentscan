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
         "  %d source(s) over %d days" % (scanned, days), ""]
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


# --------------------------------------------------------------------------
# Source: OpenClaw
#
# OpenClaw keeps per-agent transcripts in SQLite at
#   $OPENCLAW_STATE_DIR/agents/<agentId>/agent/openclaw-agent.sqlite
# documented only as "append-only, tree-structured (id + parentId)" holding
# conversation, tool calls and compaction summaries. The table and column
# names are not documented, and pinning them from a guess would break on the
# next release. So the schema is discovered at runtime and tool calls are
# recognised by shape rather than by column name.
#
# The database is opened read-only. It belongs to a running agent.
# --------------------------------------------------------------------------

import sqlite3

OPENCLAW_STATE = os.environ.get("OPENCLAW_STATE_DIR",
                                os.path.expanduser("~/.openclaw"))

# Keys that carry a tool's name, and keys that carry its arguments, across the
# shapes in circulation (Anthropic tool_use, OpenAI function calls, and the
# various framework wrappers).
_NAME_KEYS = ("name", "toolName", "tool_name", "tool", "function_name")
_ARG_KEYS = ("input", "arguments", "args", "params", "parameters", "toolInput")


def openclaw_databases(state_dir=None):
    root = state_dir or OPENCLAW_STATE
    return sorted(glob.glob(os.path.join(
        root, "agents", "*", "agent", "openclaw-agent.sqlite")))


def _open_readonly(path):
    """Read-only, and resilient to the agent holding a WAL lock."""
    try:
        conn = sqlite3.connect("file:%s?mode=ro" % path, uri=True, timeout=5)
        conn.execute("SELECT 1 FROM sqlite_master LIMIT 1")
        return conn, None
    except sqlite3.Error:
        pass
    # Live WAL: work on a copy rather than touching the agent's database.
    import shutil
    import tempfile
    tmp = tempfile.mkdtemp(prefix="agentscan-")
    copy = os.path.join(tmp, os.path.basename(path))
    try:
        shutil.copy2(path, copy)
        for suffix in ("-wal", "-shm"):
            if os.path.exists(path + suffix):
                shutil.copy2(path + suffix, copy + suffix)
        return sqlite3.connect("file:%s?mode=ro" % copy, uri=True), tmp
    except (OSError, sqlite3.Error):
        return None, tmp


_TIME_COL = re.compile(r"^(created_?at|timestamp|ts|time|updated_?at|date)$", re.I)


def _time_columns(conn, table):
    return [r[1] for r in conn.execute('PRAGMA table_info("%s")'
                                       % table.replace('"', ''))
            if _TIME_COL.match(r[1] or "")]


def _as_iso(value):
    """Rows carry epoch seconds, epoch millis or an ISO string depending on
    the writer. Normalise what we can and drop what we cannot."""
    if value in (None, ""):
        return None
    if isinstance(value, str):
        return value[:19] if value[:4].isdigit() else None
    try:
        n = float(value)
    except (TypeError, ValueError):
        return None
    if n > 1e11:          # milliseconds
        n /= 1000.0
    if n < 1e8:           # not a plausible epoch
        return None
    import datetime as _dt
    return _dt.datetime.fromtimestamp(n, _dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")


def _text_columns(conn, table):
    cols = []
    for row in conn.execute('PRAGMA table_info("%s")' % table.replace('"', '')):
        name, ctype = row[1], (row[2] or "").upper()
        if ctype in ("", "TEXT", "BLOB", "JSON") or "CHAR" in ctype:
            cols.append(name)
    return cols


def _find_tool_calls(obj, depth=0):
    """Recognise tool calls by shape, anywhere in a decoded JSON structure.

    Deduplicated: an OpenAI-style {"function": {...}} matches both the explicit
    branch and the generic walk that recurses into it.
    """
    found = _find_tool_calls_raw(obj, depth)
    out, seen = [], set()
    for name, args in found:
        key = (name, json.dumps(args, sort_keys=True, default=str)[:512])
        if key not in seen:
            seen.add(key)
            out.append((name, args))
    return out


def _find_tool_calls_raw(obj, depth=0):
    found = []
    if depth > 8:
        return found
    if isinstance(obj, list):
        for item in obj:
            found.extend(_find_tool_calls_raw(item, depth + 1))
        return found
    if not isinstance(obj, dict):
        return found

    # OpenAI-style: {"function": {"name": ..., "arguments": "<json string>"}}
    fn = obj.get("function")
    if isinstance(fn, dict) and any(k in fn for k in _NAME_KEYS):
        args = fn.get("arguments")
        if isinstance(args, str):
            try:
                args = json.loads(args)
            except ValueError:
                args = {"_raw": args}
        found.append((str(next(fn[k] for k in _NAME_KEYS if k in fn)), args or {}))

    name = next((obj[k] for k in _NAME_KEYS if isinstance(obj.get(k), str)), None)
    args = next((obj[k] for k in _ARG_KEYS if isinstance(obj.get(k), (dict, str))), None)
    if name and args is not None:
        if isinstance(args, str):
            try:
                args = json.loads(args)
            except ValueError:
                args = {"_raw": args}
        if obj.get("type") in (None, "tool_use", "tool_call", "function_call", "tool"):
            found.append((name, args))

    for value in obj.values():
        if isinstance(value, (dict, list)):
            found.extend(_find_tool_calls_raw(value, depth + 1))
        elif isinstance(value, str) and value[:1] in ("{", "["):
            try:
                found.extend(_find_tool_calls_raw(json.loads(value), depth + 1))
            except ValueError:
                pass
    return found


def scan_openclaw_db(path, source="openclaw"):
    conn, tmpdir = _open_readonly(path)
    if conn is None:
        return []

    agent_id = path.split(os.sep + "agents" + os.sep)[-1].split(os.sep)[0] \
        if os.sep + "agents" + os.sep in path else "openclaw"
    records, seen = [], set()

    try:
        tables = [r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name NOT LIKE 'sqlite_%'")]
        for table in tables:
            cols = _text_columns(conn, table)
            if not cols:
                continue
            tcols = _time_columns(conn, table)
            quoted = ", ".join('"%s"' % c.replace('"', '') for c in cols + tcols)
            try:
                rows = conn.execute('SELECT %s FROM "%s"'
                                    % (quoted, table.replace('"', '')))
            except sqlite3.Error:
                continue
            n_text = len(cols)
            for row in rows:
                stamp = next((_as_iso(v) for v in row[n_text:]
                              if _as_iso(v)), None)
                for cell in row[:n_text]:
                    if not isinstance(cell, (str, bytes)):
                        continue
                    if isinstance(cell, bytes):
                        try:
                            cell = cell.decode("utf-8")
                        except UnicodeDecodeError:
                            continue
                    if cell[:1] not in ("{", "["):
                        continue
                    try:
                        payload = json.loads(cell)
                    except ValueError:
                        continue
                    for tool, tool_input in _find_tool_calls(payload):
                        if not isinstance(tool_input, dict):
                            tool_input = {"_value": tool_input}
                        hits, text = evaluate(tool, tool_input)
                        if not hits:
                            continue
                        key = (tool, _hash(text))
                        if key in seen:
                            continue
                        seen.add(key)
                        records.append({
                            "source": source,
                            "session": agent_id,
                            "project": table,
                            "timestamp": stamp,
                            "tool_name": tool,
                            "tool_call_id": None,
                            "payload_hash": _hash(text),
                            "severity": max(
                                hits, key=lambda h: ["medium", "high", "critical"]
                                .index(h["severity"]))["severity"],
                            "hits": hits,
                        })
    finally:
        conn.close()
        if tmpdir:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)
    return records


def scan_openclaw(state_dir=None):
    records = []
    dbs = openclaw_databases(state_dir)
    for db in dbs:
        records.extend(scan_openclaw_db(db))
    return records, len(dbs)


SOURCES = ("claude-code", "openclaw")


def scan_sources(sources=SOURCES, root=None, state_dir=None, since_days=None):
    """Scan every requested local agent source into one record stream."""
    records, scanned = [], 0
    if "claude-code" in sources:
        recs, n = scan_all(root=root or CLAUDE_PROJECTS, since_days=since_days)
        records += recs
        scanned += n
    if "openclaw" in sources:
        recs, n = scan_openclaw(state_dir=state_dir)
        records += recs
        scanned += n
    records.sort(key=lambda r: r.get("timestamp") or "", reverse=True)
    return records, scanned
