# agentscan

**A flight recorder for AI agents, and a scanner for the authority they hold.**
Reads locally. Transmits nothing. No dependencies.

Your coding agent has your shell, your keys and your repo. `agentscan` reads
what it actually ran and surfaces the handful of irreversible actions worth
knowing about.

```
$ agentscan watch --days 90

  agentscan watch  · local agent flight recorder
  --------------------------------------------------------------
  4 source(s) over 90 days

  1 critical  3 high

  * Credential material accessed          18:13  Bash
      cat ~/.ssh/id_rsa
      -> Whatever it read is now in a model context you do not control.

  * Bulk or recursive deletion            14:42  Bash
      mv '@/components/'*.tsx src/components/ ; rm -rf '@'
      -> Recursive deletion. Recoverable only if something else was
         backing it up.

  --------------------------------------------------------------
  Read locally. Nothing was transmitted.
```

## Install

```bash
uvx --from git+https://github.com/MatijaMiki/agentscan agentscan watch
```

Or put it on your path:

```bash
pipx install git+https://github.com/MatijaMiki/agentscan
```

Python 3.9+. Installing with plain `pip`? Upgrade it first — the pip macOS
ships cannot read this project's metadata and will silently build a wheel
named `UNKNOWN-0.0.0` that installs fine and gives you no command.

## Two tools

### `agentscan watch` — what your agents did

Reads transcripts your agents already wrote to disk. No wrapper, no proxy,
nothing in your critical path.

| Source | Location | Format |
|---|---|---|
| Claude Code | `~/.claude/projects/*/*.jsonl` | JSONL |
| OpenClaw | `$OPENCLAW_STATE_DIR/agents/*/agent/*.sqlite` | SQLite |

Nine rules: credential access, secret literals in commands, package
publishing, cloud destruction, financial API calls, log tampering, destructive
git, recursive deletion, exfiltration-shaped pipes.

```bash
agentscan watch --days 30
agentscan watch --source openclaw
agentscan watch --json
```

### `agentscan scan` — what they're allowed to do next

Reads the credentials an agent holds, read-only, and scores the three things
that determine exposure.

| Axis | Question |
|---|---|
| Authority | What is it allowed to do? |
| Observability | Can you reconstruct a named past action? |
| Reversibility | Can a wrong action be undone? |

Observability vetoes the overall verdict. An agent that cannot reconstruct its
own tool calls is indistinguishable from the worst case.

```bash
agentscan demo                                # see it on a worked example
agentscan scan profile.json --html report.html
agentscan live --github "$GH_TOKEN"           # read-only introspection
agentscan scan profile.json --pull-usage --stripe "$STRIPE_KEY"
```

Capability catalogues for Google, GitHub, Slack, Stripe and AWS. Unrecognised
scopes are classified by action verb and flagged unclassified — never assumed
safe.

## Precision is the feature

A watcher that cries wolf gets muted in a day, and a muted watcher records
nothing anyone reads. So these are **not** treated as actions:

| Not an action | Why |
|---|---|
| `grep "rm -rf" src/` | Searching for a string isn't running it |
| `python3 -c "print('rm -rf /')"` | The payload is Python source, not shell |
| `echo "rm -rf /"` | An echo argument is literal text |
| `cat > f.sh <<'EOF' … EOF` | A heredoc body is data being written |
| `git rm --cached x` | Unstages; never touches the working tree |
| `# rm -rf ~/x` | A comment |
| `rm -rf build` `rm -rf /tmp/x` | Deleting build output is not an incident |

`bash -c` is the exception — its payload really is shell, so the parser
recurses into it. And severity follows the **target**, not the verb:
`rm -rf /tmp/x` is silent, `rm -rf ~/Documents` is high, `rm -rf /` is
critical.

Every row above came from running the tool against a real machine and finding
it wrong. On that machine the first build reported 15 findings; 3 were false
positives and 11 were true deletions of build directories that nobody would
want to read. It reports 4 now, and all four are real.

## Nothing leaves the machine

Not a policy, an architecture:

- Credentials are held in memory for one call and never written down
- Live introspection talks only to the credential's own issuer
- Scans never exercise a permission and never need a write-scoped token
- No runtime dependencies — nothing to audit before you point this at your keys

## Say what you don't know

Usage evidence has three states, reported distinctly, because collapsing them
makes the report contradict itself:

| State | Meaning |
|---|---|
| Verified | Pulled from the provider's own audit trail |
| Self-attested | Declared in the profile, not independently pulled |
| Unverified | No evidence at all — scopes are not assumed safe |

Usage pulls: AWS IAM service-last-accessed, Stripe events, Google Admin SDK,
GitHub org audit log. Slack has no usable API below Enterprise Grid and says
so rather than returning an empty set.

## Status

Alpha, honestly. The local tools ship and are tested; hosted collection and
evidence retention are not built yet.

```bash
python3 -m unittest discover -s tests -v
```

63 tests, written as invariants rather than expected output — most of them
exist because something on this page was once wrong.

## Licence

MIT. Built by cenner.
