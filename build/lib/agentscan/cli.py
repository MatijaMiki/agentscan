"""agentscan CLI.

  agentscan demo                        run against the bundled example
  agentscan scan profile.json           score a declared profile
  agentscan live --google $TOK ...      introspect real credentials locally
  agentscan scan profile.json --html out.html

Live mode never transmits a token anywhere except the issuing provider.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

from .score import scan as run_scan
from .report import render
from . import introspect
from . import usage as usage_mod
from . import watch as watch_mod


def _load(path):
    """Read a profile, failing with a message rather than a traceback."""
    try:
        with open(path) as fh:
            return json.load(fh)
    except FileNotFoundError:
        raise SystemExit("agentscan: no such file: %s" % path)
    except IsADirectoryError:
        raise SystemExit("agentscan: not a file: %s" % path)
    except PermissionError:
        raise SystemExit("agentscan: cannot read (permission denied): %s" % path)
    except ValueError as e:
        raise SystemExit("agentscan: %s is not valid JSON (%s)" % (path, e))


def _bundled(name):
    """Load data shipped inside the package."""
    try:
        from importlib.resources import files
        return json.loads(files("agentscan").joinpath("demo", name).read_text())
    except Exception:
        here = os.path.dirname(os.path.abspath(__file__))
        return _load(os.path.join(here, "demo", name))


def _pull_usage(profile, args):
    """Best-effort usage pulls. A provider that cannot report usage is left
    explicitly unverified rather than silently empty."""
    results = {}
    providers = {c.get("provider") for c in profile.get("credentials", [])}

    for provider in sorted(providers & set(usage_mod.PULLS)):
        token = getattr(args, provider, None)
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


def main(argv=None):
    p = argparse.ArgumentParser(prog="agentscan",
                                description="Score an AI agent's authority, observability and reversibility.")
    p.add_argument("command", choices=["demo", "scan", "live", "watch"])
    p.add_argument("profile", nargs="?", help="path to a profile JSON")
    p.add_argument("--json", action="store_true", help="emit raw JSON")
    p.add_argument("--html", metavar="PATH", help="also write an HTML report")
    for name in introspect.PROVIDERS:
        p.add_argument("--%s" % name, metavar="TOKEN",
                       help="%s credential to introspect (read-only)" % name)
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
    args = p.parse_args(argv)

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
        token = getattr(args, name, None)
        if not token:
            continue
        try:
            creds.append(fn(token))
        except introspect.IntrospectionError as e:
            errors.append("%s: %s" % (name, e))
    if not creds:
        print("No credentials introspected. %s" % ("; ".join(errors) or
              "Pass at least one of --google/--github/--slack/--stripe."),
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
