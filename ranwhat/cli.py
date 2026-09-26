"""ranwhat CLI.

  ranwhat demo                        run against the bundled example
  ranwhat scan profile.json           score a declared profile
  ranwhat live --google $TOK ...      introspect real credentials locally
  ranwhat scan profile.json --html out.html

Live mode never transmits a token anywhere except the issuing provider.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import time

from .score import scan as _run_scan, ProfileError
from .report import render
from . import introspect
from . import usage as usage_mod
from . import watch as watch_mod
from . import clean as clean_mod
from . import feed as feed_mod
from . import catalog as catalog_mod


def _token(args, provider):
    """Resolve a credential without requiring it on the command line.

    Anything in argv is world-readable through the process table for as long
    as the process runs, and is written to shell history besides. The
    environment variable is the documented path; a literal flag still works
    but says so.
    """
    env_name = "RANWHAT_%s_TOKEN" % provider.upper()
    value = getattr(args, provider, None)

    if value == "-":
        value = sys.stdin.readline().strip()
    elif value and value.startswith("env:"):
        var = value[4:]
        value = os.environ.get(var)
        if not value:
            raise SystemExit("ranwhat: %s is empty or unset" % var)
    elif value:
        print("  warning: --%s put a credential in this machine's process "
              "table. Use %s instead." % (provider, env_name), file=sys.stderr)

    return value or os.environ.get(env_name)


def run_scan(profile):
    """Score a profile, turning a malformed one into a message."""
    try:
        return _run_scan(profile)
    except ProfileError as e:
        raise SystemExit("ranwhat: %s" % e)


def _load(path):
    """Read a profile, failing with a message rather than a traceback."""
    try:
        with open(path) as fh:
            return json.load(fh)
    except FileNotFoundError:
        raise SystemExit("ranwhat: no such file: %s" % path)
    except IsADirectoryError:
        raise SystemExit("ranwhat: not a file: %s" % path)
    except PermissionError:
        raise SystemExit("ranwhat: cannot read (permission denied): %s" % path)
    except ValueError as e:
        raise SystemExit("ranwhat: %s is not valid JSON (%s)" % (path, e))


def _bundled(name):
    """Load data shipped inside the package."""
    try:
        from importlib.resources import files
        return json.loads(files("ranwhat").joinpath("demo", name).read_text())
    except Exception:
        here = os.path.dirname(os.path.abspath(__file__))
        return _load(os.path.join(here, "demo", name))


def _pull_usage(profile, args):
    """Best-effort usage pulls. A provider that cannot report usage is left
    explicitly unverified rather than silently empty."""
    results = {}
    providers = {c.get("provider") for c in profile.get("credentials", [])}

    for provider in sorted(providers & set(usage_mod.PULLS)):
        token = _token(args, provider)
        try:
            if provider == "aws":
                results["aws"] = usage_mod.aws_usage(
                    profile=args.aws_profile, window_days=args.window_days)
            elif provider == "github":
                if not token:
                    continue
                results["github"] = usage_mod.github_usage(
                    token, org=args.github_org, window_days=args.window_days)
            elif token:
                results[provider] = usage_mod.PULLS[provider](
                    token, window_days=args.window_days)
            else:
                continue
            print("  usage: %-8s %s" % (provider, results[provider][1].level),
                  file=sys.stderr)
        except introspect.IntrospectionError as e:
            print("  usage: %-8s unavailable (%s)" % (provider, e), file=sys.stderr)

    if results:
        usage_mod.apply_usage(profile, results)
    return profile


def _emit(result, args):
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(render(result))
    if args.html:
        from .html_report import write_html
        write_html(result, args.html)
        print("  html report: %s\n" % args.html)


OVERVIEW = """
  ranwhat  \u00b7 find out what your AI agents actually did

  watch    what your agents already ran on this machine
  clean    credentials sitting in plaintext in agent transcripts
  scan     the authority a set of credentials carries
  demo     see the output without setting anything up
  update   refresh the capability catalogue (needs a subscription)

  Start here:
    %(cmd)s demo
    %(cmd)s watch --days 30

  Everything runs locally. No account, and nothing is transmitted.
  Full options: %(cmd)s --help
"""


def invocation():
    """How to spell a follow-up command so it works the way this one did.

    `uvx ranwhat` runs from a throwaway environment that is not on PATH, so
    telling that user to run `ranwhat demo` sends them to command-not-found.
    Suggest whichever form actually resolves to the file being executed.
    """
    try:
        running = os.path.realpath(sys.argv[0] or "")
        on_path = shutil.which("ranwhat")
        if on_path and os.path.realpath(on_path) == running:
            return "ranwhat"
    except OSError:
        pass
    return "uvx ranwhat"


def _overview(parser):
    """Shown for a bare `ranwhat`, instead of an argparse usage error."""
    sys.stdout.write(OVERVIEW.lstrip("\n") % {"cmd": invocation()})


def _update(args):
    """Fetch the subscribed catalogue, or report what is cached.

    Deliberately the only command that touches the network, and it sends a
    token and nothing else.
    """
    if args.status:
        st = feed_mod.status()
        if not st["active"]:
            sys.stdout.write(
                "  No feed cached. The bundled catalogue is in use.\n"
                "  A subscription adds providers as they ship new scopes:\n"
                "  https://ranwhat.com/pricing\n")
            return 0
        when = time.strftime("%Y-%m-%d %H:%M", time.localtime(st["fetched_at"]))
        sys.stdout.write(
            "  Feed %s\n  %d providers, %d scopes\n  fetched %s\n"
            % (st.get("version") or "?", st["providers"], st["scopes"], when))
        return 0

    token = args.token or feed_mod.read_token()
    if not token:
        sys.stderr.write(
            "  No token. Set RANWHAT_TOKEN, or pass --token with --save-token\n"
            "  to store it at ~/.ranwhat/token.\n\n"
            "  Everything else works without one; the feed only keeps the\n"
            "  capability catalogue current. https://ranwhat.com/pricing\n")
        return 1
    if args.token:
        sys.stderr.write(
            "  Warning: a token in the command line is readable by every user\n"
            "  on this machine through the process table, and is written to\n"
            "  your shell history. Prefer RANWHAT_TOKEN.\n\n")

    try:
        doc = feed_mod.fetch(token)
    except feed_mod.FeedError as exc:
        sys.stderr.write("  %s\n" % exc)
        return 1

    feed_mod.save(doc)
    if args.save_token:
        path = feed_mod.save_token(token)
        sys.stdout.write("  Token saved to %s (0600)\n" % path)
    catalog_mod.reset_feed_cache()

    cat = doc.get("catalogue", {})
    sys.stdout.write(
        "  Updated to feed %s\n  %d providers, %d scopes\n"
        % (doc.get("version") or "?", len(cat), sum(len(v) for v in cat.values())))
    return 0

def main(argv=None):
    p = argparse.ArgumentParser(prog="ranwhat",
                                description="Score an AI agent's authority, observability and reversibility.")
    p.add_argument("command", nargs="?",
                   choices=["demo", "scan", "live", "watch", "clean", "update"])
    p.add_argument("profile", nargs="?", help="path to a profile JSON")
    p.add_argument("--json", action="store_true", help="emit raw JSON")
    p.add_argument("--html", metavar="PATH", help="also write an HTML report")
    for name in introspect.PROVIDERS:
        p.add_argument("--%s" % name, metavar="TOKEN",
                       help="%s credential. Prefer RANWHAT_%s_TOKEN in the "
                            "environment: a value passed here is visible to "
                            "every user on this machine via ps, and lands in "
                            "your shell history."
                            % (name, name.upper()))
    p.add_argument("--controls", metavar="PATH",
                   help="controls JSON to pair with live introspection")
    p.add_argument("--pull-usage", action="store_true",
                   help="pull real usage data to establish which granted "
                        "permissions were actually exercised (read-only)")
    p.add_argument("--aws-profile", metavar="NAME", help="AWS CLI profile for usage pull")
    p.add_argument("--github-org", metavar="ORG", help="GitHub org for audit-log usage pull")
    p.add_argument("--window-days", type=int, default=usage_mod.DEFAULT_WINDOW_DAYS,
                   help="usage lookback window (default 90)")
    p.add_argument("--days", type=int, default=30,
                   help="watch: how far back to read local agent history")
    p.add_argument("--root", metavar="PATH", default=watch_mod.CLAUDE_PROJECTS,
                   help="watch: Claude Code transcript directory")
    p.add_argument("--state-dir", metavar="PATH",
                   help="watch: OpenClaw state directory (default ~/.openclaw)")
    p.add_argument("--source", action="append", choices=list(watch_mod.SOURCES),
                   help="watch: limit to a source (repeatable; default all)")
    p.add_argument("--apply", action="store_true",
                   help="clean: mask everything found without asking. Without "
                        "it, clean reports and then opens a review session.")
    p.add_argument("--no-interactive", action="store_true",
                   help="clean: report and exit instead of opening the review "
                        "session")
    p.add_argument("--token", metavar="TOKEN",
                   help="update: subscription token. Prefer RANWHAT_TOKEN in "
                        "the environment, or run update once to save it: a "
                        "value passed here is visible to every user on this "
                        "machine via ps, and lands in your shell history.")
    p.add_argument("--save-token", action="store_true",
                   help="update: write the token to ~/.ranwhat/token (0600) "
                        "so later runs need no flag")
    p.add_argument("--status", action="store_true",
                   help="update: report the cached feed and exit without "
                        "touching the network")
    args = p.parse_args(argv)

    if args.command is None:
        _overview(p)
        return 0

    if args.command == "update":
        return _update(args)


    if args.days is not None and args.days < 1:
        p.error("--days must be at least 1")
    if args.window_days is not None and args.window_days < 1:
        p.error("--window-days must be at least 1")

    if args.command == "clean":
        def _progress(i, total, path):
            if args.json:
                return
            sys.stderr.write("\r  scanning %d/%d %-34s" % (
                i, total, os.path.basename(os.path.dirname(path))[-34:]))
            sys.stderr.flush()

        findings, scanned, changed = clean_mod.scan(
            root=args.root, since_days=args.days, apply=args.apply,
            progress=_progress)
        if not args.json:
            sys.stderr.write("\r" + " " * 60 + "\r")
        if args.json:
            print(json.dumps({"scanned": scanned, "applied": args.apply,
                              "changed": changed,
                              "findings": [dict(f, files=sorted(f["files"]))
                                           for f in findings.values()]}, indent=2))
        else:
            print(clean_mod.render(findings, scanned, changed, args.apply))
            # The findings are already in memory; making someone re-scan a
            # large history just to act on what they read is wasteful.
            if (findings and not args.apply and not args.no_interactive
                    and sys.stdin.isatty()):
                clean_mod.review(findings, scanned)
        return 0

    if args.command == "watch":
        records, n = watch_mod.scan_sources(
            sources=args.source or watch_mod.SOURCES,
            root=args.root, state_dir=args.state_dir, since_days=args.days)
        if args.json:
            print(json.dumps(records, indent=2))
        else:
            print(watch_mod.render(records, n, args.days))
        return 0

    if args.command == "demo":
        _emit(run_scan(_bundled("support-copilot.json")), args)
        return 0

    if args.command == "scan":
        if not args.profile:
            p.error("scan requires a profile path")
        profile = _load(args.profile)
        if args.pull_usage:
            profile = _pull_usage(profile, args)
        _emit(run_scan(profile), args)
        return 0

    # live
    creds, errors = [], []
    for name, fn in introspect.PROVIDERS.items():
        token = _token(args, name)
        if not token:
            continue
        try:
            creds.append(fn(token))
        except introspect.IntrospectionError as e:
            errors.append("%s: %s" % (name, e))
    if not creds:
        print("No credentials introspected. %s" % ("; ".join(errors) or
              "Set RANWHAT_<PROVIDER>_TOKEN, or pass --google/--github/"
              "--slack/--stripe."),
              file=sys.stderr)
        return 1
    for e in errors:
        print("  warning: %s" % e, file=sys.stderr)

    controls = _load(args.controls) if args.controls else {}
    profile = {"agent": "live-scan", "credentials": creds, "controls": controls}
    if args.pull_usage:
        profile = _pull_usage(profile, args)
    _emit(run_scan(profile), args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
