# agentscan

Scores an AI agent's **authority**, **observability** and **reversibility** —
the three axes agent-liability underwriters price on — and produces the report
that makes the agent insurable.

Not a scanner that looks for bugs. A scanner that answers the question a broker
or a plaintiff will ask: *what is this agent allowed to do, and can you prove
what it did?*

## Why these three

| Axis | Question | Why it prices |
|---|---|---|
| Authority | What is it allowed to do? | Loss is determined by what the agent did *and where it had permission to do it*. |
| Observability | Can you reconstruct a named past action? | An agent that cannot reconstruct its tool calls is indistinguishable from the worst case, and is rated as such. |
| Reversibility | Can a wrong action be undone? | Determines whether an incident is a correction or a claim. |

Observability can veto the whole result. That is deliberate — it mirrors how
these deployments are actually rated.

## Use

```bash
python3 -m agentscan.cli demo                          # bundled example
python3 -m agentscan.cli scan profile.json             # score a declared profile
python3 -m agentscan.cli scan profile.json --html out.html
python3 -m agentscan.cli scan profile.json --json
```

Live, read-only introspection of real credentials:

```bash
python3 -m agentscan.cli live --google "$GOOGLE_TOKEN" --github "$GH_TOKEN" \
  --controls controls.json
```

## Where things run

| Component | Runs | Holds |
|---|---|---|
| Scanner (this CLI) | Your machine / your CI | Credentials, in memory, for one call |
| Collector | Your infrastructure | Payloads, hashed in place |
| Dashboard & Trust Page | Hosted | Derived metadata only |

**No credential, prompt, message body or customer record is ever transmitted.**
Live mode talks only to the credential's own issuer. That is the architecture,
not a policy — it is why this can be adopted without a security review.

## Profile format

```json
{
  "agent": "support-copilot",
  "credentials": [
    { "provider": "stripe",
      "label": "live key",
      "scopes": ["refunds:write", "customers:read"],
      "scopes_used": ["refunds:write"] }
  ],
  "controls": {
    "human_approval": "none | financial_only | all",
    "spend_cap_usd": null,
    "kill_switch": false,
    "trace_retention_days": 14,
    "tool_call_attributes": false,
    "tamper_evident": false
  }
}
```

`scopes_used` is optional. Omitting it is itself a finding — you cannot
demonstrate least privilege without it.

Providers with built-in capability catalogs: `google`, `github`, `slack`,
`stripe`, `aws`. Anything else is classified by action verb and flagged
unclassified rather than silently assumed safe.

## Usage pulls

`scopes_used` can be supplied by hand, or pulled from the provider:

```bash
python3 -m agentscan.cli scan profile.json --pull-usage \
  --stripe "$STRIPE_KEY" --github "$GH_TOKEN" --github-org acme \
  --aws-profile agent-role --window-days 90
```

Coverage is honest per provider, because an unverified provider that silently
returned an empty set would turn every one of its scopes into a false critical:

| Provider | Source | Coverage | Needs |
|---|---|---|---|
| AWS | IAM service-last-accessed | Full, per-service | `aws` CLI, `iam:GenerateServiceLastAccessedDetails` |
| Stripe | `/v1/events` | Writes only | Any API key |
| Google | Admin SDK token reports | Full | Workspace admin + `admin.reports.audit.readonly` |
| GitHub | Org audit log | Full | Enterprise Cloud + `read:audit_log` |
| Slack | — | None | Audit API is Enterprise Grid only |

Writes-only coverage is not a partial product. The findings that matter —
financial, destructive, irreversible — are exactly the ones that leave a
record in an event stream.

## Status

- [x] **Credential authority** — no integration required
- [x] **Usage pulls** — AWS, Stripe, Google, GitHub, with explicit coverage gaps
- [ ] Static config scan (spend caps, approval gates, kill switch, instrumentation)
- [ ] Reconstruction test against live traces
- [ ] Local agent watch (OpenClaw / Claude Code / Codex / MCP)
- [ ] Adversarial probe (opt-in, staging only)
