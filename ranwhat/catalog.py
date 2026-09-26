"""
Scope catalog: what each granted permission actually lets an agent do.

This is the core of the scan. Introspection tells you an agent holds
"https://www.googleapis.com/auth/gmail.send". It does not tell you that this
is an irreversible, externally-visible write that no underwriter will price
without a human-approval gate. That mapping lives here.

Fields per scope:
  label        human-readable capability
  authority    read | write | financial | destructive
  reversible   can the action be undone after the fact
  blast        which blast-radius dimension it opens
  why          the sentence that goes in the report
"""

from __future__ import annotations

READ, WRITE, FINANCIAL, DESTRUCTIVE = "read", "write", "financial", "destructive"

AUTHORITY_RANK = {READ: 0, WRITE: 1, FINANCIAL: 2, DESTRUCTIVE: 3}

# blast-radius dimensions
MONETARY = "monetary"
EXTERNAL_COMMS = "external_comms"
DATA_EGRESS = "data_egress"
INFRASTRUCTURE = "infrastructure"
IDENTITY = "identity"


def _s(label, authority, reversible, blast, why):
    return {
        "label": label,
        "authority": authority,
        "reversible": reversible,
        "blast": blast,
        "why": why,
    }


CATALOG = {
    "google": {
        "https://www.googleapis.com/auth/gmail.readonly": _s(
            "Read all mail", READ, True, DATA_EGRESS,
            "Full mailbox read. Every message the agent can see is exfiltratable "
            "by a prompt injection delivered in any one of them."),
        "https://www.googleapis.com/auth/gmail.send": _s(
            "Send mail as the user", WRITE, False, EXTERNAL_COMMS,
            "Can email any external party as the user. Sent mail cannot be recalled."),
        "https://www.googleapis.com/auth/gmail.modify": _s(
            "Read, send, modify and label mail", WRITE, False, EXTERNAL_COMMS,
            "Superset of read+send. Can also hide its own activity by "
            "relabelling or archiving the evidence."),
        "https://mail.google.com/": _s(
            "Full mailbox control including permanent delete", DESTRUCTIVE, False, DATA_EGRESS,
            "Total mailbox authority including irreversible deletion. This is the "
            "broadest Gmail scope that exists."),
        "https://www.googleapis.com/auth/calendar": _s(
            "Read/write calendar", WRITE, True, EXTERNAL_COMMS,
            "Can create events that email external attendees."),
        "https://www.googleapis.com/auth/calendar.readonly": _s(
            "Read calendar", READ, True, DATA_EGRESS,
            "Reveals meeting topics, attendees and internal org structure."),
        "https://www.googleapis.com/auth/drive": _s(
            "Full Drive access", DESTRUCTIVE, False, DATA_EGRESS,
            "Read, write, share and permanently delete any file. Sharing is an "
            "egress path that leaves no trace in most DLP tooling."),
        "https://www.googleapis.com/auth/drive.file": _s(
            "Drive access limited to files the app created", WRITE, True, DATA_EGRESS,
            "Correctly scoped. This is what most Drive integrations should use."),
        "https://www.googleapis.com/auth/drive.readonly": _s(
            "Read all Drive files", READ, True, DATA_EGRESS,
            "Full document corpus is readable, and therefore summarisable into "
            "any outbound channel the agent also holds."),
        "https://www.googleapis.com/auth/contacts": _s(
            "Read/write contacts", WRITE, True, DATA_EGRESS,
            "Contact list is the target list for any outbound abuse."),
        "https://www.googleapis.com/auth/cloud-platform": _s(
            "Full Google Cloud control", DESTRUCTIVE, False, INFRASTRUCTURE,
            "Complete control of the GCP project including billing, IAM and "
            "resource deletion."),
    },
    "github": {
        "repo": _s(
            "Full control of private repositories", WRITE, False, DATA_EGRESS,
            "Read and write all private source. Includes force-push, which can "
            "rewrite history and destroy the audit trail."),
        "public_repo": _s(
            "Write access to public repositories", WRITE, False, DATA_EGRESS,
            "Can publish to public repos. A misdirected commit is a permanent "
            "public disclosure."),
        "delete_repo": _s(
            "Delete repositories", DESTRUCTIVE, False, INFRASTRUCTURE,
            "Irreversible destruction of a repository. Almost never needed by an agent."),
        "admin:org": _s(
            "Full organisation administration", DESTRUCTIVE, False, IDENTITY,
            "Can add and remove org members, i.e. can grant persistence to an attacker."),
        "workflow": _s(
            "Update GitHub Actions workflows", DESTRUCTIVE, False, INFRASTRUCTURE,
            "Can modify CI. A workflow edit is arbitrary code execution with your "
            "CI secrets attached."),
        "write:packages": _s(
            "Publish packages", WRITE, False, INFRASTRUCTURE,
            "Can publish artifacts consumed downstream. Supply-chain reach."),
        "read:org": _s(
            "Read org membership", READ, True, IDENTITY,
            "Low risk on its own."),
        "gist": _s(
            "Create gists", WRITE, False, DATA_EGRESS,
            "A public gist is a one-call exfiltration primitive."),
    },
    "slack": {
        "chat:write": _s(
            "Post messages", WRITE, False, EXTERNAL_COMMS,
            "Can post as the app into any channel it is in. Messages are seen "
            "before they can be deleted."),
        "channels:history": _s(
            "Read public channel history", READ, True, DATA_EGRESS,
            "Full public conversation history is readable."),
        "groups:history": _s(
            "Read private channel history", READ, True, DATA_EGRESS,
            "Private channel content. Usually the most sensitive text in a company."),
        "im:history": _s(
            "Read direct messages", READ, True, DATA_EGRESS,
            "DM content. Rarely justifiable for an agent."),
        "files:read": _s(
            "Read files", READ, True, DATA_EGRESS,
            "All shared files including exports and credentials pasted as snippets."),
        "users:read.email": _s(
            "Read user email addresses", READ, True, IDENTITY,
            "Directory of addressable humans."),
        "admin": _s(
            "Workspace administration", DESTRUCTIVE, False, IDENTITY,
            "Full workspace control."),
    },
    "stripe": {
        "charges:write": _s(
            "Create and capture charges", FINANCIAL, False, MONETARY,
            "Can move customer money. Settled charges are reversible only via "
            "refund, which is a separate, slower, partially-fee-bearing action."),
        "refunds:write": _s(
            "Issue refunds", FINANCIAL, False, MONETARY,
            "Can pay money out. This is the single most commonly abused agent "
            "capability in reported incidents."),
        "transfers:write": _s(
            "Move money to connected accounts", FINANCIAL, False, MONETARY,
            "Outbound transfer authority. Effectively irreversible once settled."),
        "payment_intents:write": _s(
            "Create payment intents", FINANCIAL, True, MONETARY,
            "Initiates payment flows."),
        "customers:read": _s(
            "Read customer records", READ, True, DATA_EGRESS,
            "PII and payment metadata for the full customer base."),
        "customers:write": _s(
            "Modify customer records", WRITE, True, IDENTITY,
            "Can change the email on a customer record, which is an account-takeover "
            "primitive in most billing flows."),
        "all": _s(
            "Unrestricted secret key", DESTRUCTIVE, False, MONETARY,
            "A live secret key with no restrictions. Every Stripe capability, "
            "including payouts, is available to whatever holds this."),
    },
    "aws": {
        "*": _s(
            "Full AWS administrator", DESTRUCTIVE, False, INFRASTRUCTURE,
            "Unrestricted control of the account including IAM, billing and deletion."),
        "s3:*": _s(
            "Full S3 control", DESTRUCTIVE, False, DATA_EGRESS,
            "Read, write, make-public and delete every bucket. Covers both the "
            "egress path and the destruction of the logs that would record it."),
        "s3:GetObject": _s(
            "Read objects", READ, True, DATA_EGRESS,
            "Object read."),
        "s3:PutObject": _s(
            "Write objects", WRITE, True, DATA_EGRESS,
            "Object write."),
        "s3:DeleteObject": _s(
            "Delete objects", DESTRUCTIVE, False, DATA_EGRESS,
            "Irreversible unless versioning is on."),
        "iam:*": _s(
            "Full IAM control", DESTRUCTIVE, False, IDENTITY,
            "Can grant itself any other permission. This makes every other scope "
            "limit on this credential decorative."),
        "ses:SendEmail": _s(
            "Send email", WRITE, False, EXTERNAL_COMMS,
            "Outbound email from your verified domain."),
        "lambda:InvokeFunction": _s(
            "Invoke functions", WRITE, True, INFRASTRUCTURE,
            "Arbitrary invocation of deployed code."),
    },
    "generic": {},
}


# Verb inference for scopes not in the catalog. Cloud providers mint new
# actions constantly; guessing from the verb is far more accurate than
# inheriting the severity of a broad wildcard entry.
_READ_VERBS = ("get", "list", "describe", "read", "view", "search", "query", "head")
_DESTRUCTIVE_VERBS = ("delete", "terminate", "destroy", "remove", "purge", "revoke", "drop")
_FINANCIAL_HINTS = ("payment", "charge", "refund", "payout", "transfer", "invoice", "billing")


def _infer(provider, scope):
    """Classify an unrecognised scope from its action verb."""
    tail = scope.split(":")[-1].split(".")[-1].split("/")[-1].lower()
    lowered = scope.lower()

    if any(h in lowered for h in _FINANCIAL_HINTS) and not tail.startswith(_READ_VERBS):
        authority, reversible, blast = FINANCIAL, False, MONETARY
    elif tail.startswith(_DESTRUCTIVE_VERBS):
        authority, reversible, blast = DESTRUCTIVE, False, INFRASTRUCTURE
    elif tail.startswith(_READ_VERBS):
        authority, reversible, blast = READ, True, DATA_EGRESS
    else:
        authority, reversible, blast = WRITE, False, DATA_EGRESS

    entry = _s(
        scope, authority, reversible, blast,
        "Not in the capability catalog. Classified as %s from its action verb. "
        "Confirm this manually before relying on the score." % authority,
    )
    entry["known"] = False
    return entry


_FEED_CACHE = []   # one slot; [] means "not looked yet", [None] means "no feed"


def _feed_catalogue():
    """The subscribed catalogue if one is cached, else None.

    Read once per process and never over the network: a scan must not depend
    on a server being reachable, and must not slow down because one is not.
    """
    if not _FEED_CACHE:
        try:
            from . import feed
            doc = feed.load()
            _FEED_CACHE.append(doc.get("catalogue") if doc else None)
        except Exception:
            _FEED_CACHE.append(None)
    return _FEED_CACHE[0]


def reset_feed_cache():
    """Drop the memoised feed. For tests, and after `ranwhat update`."""
    del _FEED_CACHE[:]


def providers(provider):
    """Bundled entries for a provider, overlaid with any feed entries.

    The feed wins per scope rather than per provider, so a feed that has not
    caught up with a locally known scope cannot remove it.
    """
    merged = dict(CATALOG.get(provider, {}))
    fed = _feed_catalogue()
    if fed:
        merged.update(fed.get(provider, {}))
    return merged


def lookup(provider, scope):
    """Resolve a granted scope to its capability entry.

    An exact catalog hit wins. A granted scope that is itself a wildcard
    (e.g. "s3:*") matches the catalog wildcard. A narrow granted scope is
    NEVER widened to a broad wildcard entry -- being granted s3:ListBucket
    is not the same as being granted s3:*, and scoring it that way would
    make the whole report untrustworthy.

    A subscribed feed entry overrides the bundled one for the same scope, and
    adds scopes the bundle never had. Everything below is unchanged by that:
    the feed supplies data, not different rules.
    """
    prov = providers(provider)
    if scope in prov:
        entry = dict(prov[scope])
        entry["known"] = True
        return entry

    if scope.endswith("*"):
        wildcards = sorted([s for s in prov if s.endswith("*")], key=len, reverse=True)
        for pattern in wildcards:
            if scope.startswith(pattern[:-1]):
                entry = dict(prov[pattern])
                entry["known"] = True
                entry["label"] = "%s (matched %s)" % (entry["label"], pattern)
                return entry

    return _infer(provider, scope)
