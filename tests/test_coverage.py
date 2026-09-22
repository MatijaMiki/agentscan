"""Regression tests for usage-evidence classification.

The bug these exist to prevent: the report simultaneously claiming that N
permissions were never used, and that usage could not be verified for the
providers those permissions belong to. A report that contradicts itself is
worse than no report.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agentscan import usage
from agentscan.score import scan


def _finding(result, fragment):
    for f in result["findings"]:
        if fragment in f["title"]:
            return f
    return None


def _profile(**kw):
    base = {
        "agent": "t",
        "credentials": [
            {"provider": "slack", "label": "s",
             "scopes": ["chat:write", "im:history"]},
        ],
        "controls": {},
    }
    base.update(kw)
    return base


class CoverageStates(unittest.TestCase):

    def test_no_data_is_unverified(self):
        r = scan(_profile())
        self.assertIsNotNone(_finding(r, "could not be determined"))
        self.assertIsNone(_finding(r, "self-attested"))
        self.assertEqual(r["counts"]["unused"], 0)

    def test_declared_usage_is_self_attested_not_unverified(self):
        p = _profile()
        p["credentials"][0]["scopes_used"] = ["chat:write"]
        r = scan(p)
        self.assertIsNotNone(_finding(r, "self-attested"))
        self.assertIsNone(_finding(r, "could not be determined"))
        self.assertEqual(r["counts"]["unused"], 1)

    def test_pulled_usage_is_neither(self):
        p = _profile()
        usage.apply_usage(p, {"slack": (["chat:write"], usage.Coverage(
            "slack", usage.Coverage.FULL, "audit log", 90))})
        r = scan(p)
        self.assertIsNone(_finding(r, "self-attested"))
        self.assertIsNone(_finding(r, "could not be determined"))

    def test_failed_pull_does_not_fake_empty_usage(self):
        """A provider that cannot report usage must not read as 'nothing used'."""
        p = _profile()
        p["credentials"][0]["scopes_used"] = ["chat:write"]
        usage.apply_usage(p, {"slack": ([], usage.Coverage(
            "slack", usage.Coverage.NONE, "not enterprise grid", 90))})
        r = scan(p)
        self.assertEqual(r["counts"]["unused"], 0,
                         "a failed pull must not manufacture never-used findings")
        self.assertIsNotNone(_finding(r, "could not be determined"))


class ReportConsistency(unittest.TestCase):

    def test_never_used_claims_have_evidence(self):
        """THE invariant: no provider may appear in an unused-permission
        finding while also being listed as unverified."""
        p = {
            "agent": "mixed",
            "credentials": [
                {"provider": "stripe", "label": "a",
                 "scopes": ["refunds:write", "transfers:write"],
                 "scopes_used": ["refunds:write"]},
                {"provider": "slack", "label": "b",
                 "scopes": ["chat:write", "im:history"]},
            ],
            "controls": {},
        }
        r = scan(p)
        unverified = set((_finding(r, "could not be determined") or
                          {"evidence": []})["evidence"])
        unused_providers = {row["provider"] for row in r["scopes"]
                            if row["usage"] == "unused"}
        self.assertFalse(unverified & unused_providers,
                         "provider is both unverified and reported as never-used")


class Classification(unittest.TestCase):

    def test_narrow_scope_not_widened_to_wildcard(self):
        from agentscan.catalog import lookup
        self.assertEqual(lookup("aws", "s3:ListBucket")["authority"], "read")
        self.assertEqual(lookup("aws", "s3:*")["authority"], "destructive")

    def test_unknown_scope_flagged_not_assumed_safe(self):
        from agentscan.catalog import lookup
        e = lookup("notion", "databases:delete")
        self.assertFalse(e["known"])
        self.assertEqual(e["authority"], "destructive")

    def test_observability_vetoes_verdict(self):
        p = _profile(controls={"trace_retention_days": 0,
                               "tool_call_attributes": False})
        self.assertEqual(scan(p)["verdict"]["status"], "UNINSURABLE")


if __name__ == "__main__":
    unittest.main(verbosity=2)
