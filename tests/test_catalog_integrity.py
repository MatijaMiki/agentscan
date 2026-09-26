"""Structural guarantees for the catalogue.

Worth having twice over now: entries also arrive from the feed, so the shape
these tests enforce is the contract a served catalogue has to meet.
"""
import unittest

from ranwhat import catalog


VALID_AUTHORITY = {catalog.READ, catalog.WRITE, catalog.FINANCIAL, catalog.DESTRUCTIVE}
VALID_BLAST = {catalog.MONETARY, catalog.EXTERNAL_COMMS, catalog.DATA_EGRESS,
               catalog.INFRASTRUCTURE, catalog.IDENTITY}


def entries():
    for provider, scopes in catalog.CATALOG.items():
        for scope, entry in scopes.items():
            yield provider, scope, entry


class Shape(unittest.TestCase):
    def test_every_entry_has_every_field(self):
        for provider, scope, e in entries():
            for field in ("label", "authority", "reversible", "blast", "why"):
                self.assertIn(field, e, "%s/%s missing %s" % (provider, scope, field))

    def test_authority_is_a_known_value(self):
        for provider, scope, e in entries():
            self.assertIn(e["authority"], VALID_AUTHORITY,
                          "%s/%s has authority %r" % (provider, scope, e["authority"]))

    def test_blast_is_a_known_dimension(self):
        for provider, scope, e in entries():
            self.assertIn(e["blast"], VALID_BLAST,
                          "%s/%s has blast %r" % (provider, scope, e["blast"]))

    def test_reversible_is_a_bool(self):
        """Scoring branches on this. A truthy string would read as reversible."""
        for provider, scope, e in entries():
            self.assertIsInstance(e["reversible"], bool,
                                  "%s/%s reversible is %r" % (provider, scope, e["reversible"]))

    def test_every_entry_explains_itself(self):
        """The `why` is the sentence that reaches the report. Empty is useless."""
        for provider, scope, e in entries():
            self.assertTrue(e["why"].strip(), "%s/%s has no why" % (provider, scope))
            self.assertTrue(e["label"].strip(), "%s/%s has no label" % (provider, scope))


class Semantics(unittest.TestCase):
    def test_destructive_scopes_are_not_marked_reversible(self):
        """If a thing can destroy data, calling it reversible understates it."""
        for provider, scope, e in entries():
            if e["authority"] == catalog.DESTRUCTIVE:
                self.assertFalse(e["reversible"],
                                 "%s/%s is destructive but marked reversible"
                                 % (provider, scope))

    def test_financial_scopes_carry_monetary_blast(self):
        for provider, scope, e in entries():
            if e["authority"] == catalog.FINANCIAL:
                self.assertEqual(e["blast"], catalog.MONETARY,
                                 "%s/%s is financial but blast is %r"
                                 % (provider, scope, e["blast"]))

    def test_no_duplicate_scope_within_a_provider(self):
        for provider, scopes in catalog.CATALOG.items():
            self.assertEqual(len(scopes), len(set(scopes)), provider)


class Coverage(unittest.TestCase):
    def test_catalogue_covers_the_providers_the_site_claims(self):
        """The site sells breadth. If a provider is dropped, this fails first."""
        for provider in ("google", "github", "slack", "stripe", "aws",
                         "atlassian", "microsoft", "sentry", "shopify",
                         "hubspot", "discord", "gitlab"):
            self.assertIn(provider, catalog.CATALOG)
            self.assertTrue(catalog.CATALOG[provider], "%s is empty" % provider)


if __name__ == "__main__":
    unittest.main()
