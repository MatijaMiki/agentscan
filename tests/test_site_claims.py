"""The site states numbers that come from the catalogue. Those numbers drift
the moment a provider is added, and a marketing page that undercounts its own
product is the kind of thing nobody notices for months."""
import pathlib
import re
import unittest

from ranwhat import catalog

SITE = pathlib.Path(__file__).resolve().parent.parent / "site"


def live():
    providers = {p: s for p, s in catalog.CATALOG.items() if s}
    return len(providers), sum(len(s) for s in providers.values())


class SiteMatchesCatalogue(unittest.TestCase):
    def test_about_page_counts_are_current(self):
        n_prov, n_scopes = live()
        text = (SITE / "about.html").read_text()
        self.assertIn("%d providers and %d permissions" % (n_prov, n_scopes), text,
                      "about.html coverage numbers are stale")

    def test_about_page_lists_every_provider(self):
        text = (SITE / "about.html").read_text()
        display = {
            "google": "Google Workspace", "github": "GitHub", "gitlab": "GitLab",
            "microsoft": "Microsoft 365", "slack": "Slack", "discord": "Discord",
            "stripe": "Stripe", "shopify": "Shopify", "hubspot": "HubSpot",
            "atlassian": "Atlassian", "sentry": "Sentry", "aws": "AWS",
        }
        for provider, scopes in catalog.CATALOG.items():
            if not scopes:
                continue
            self.assertIn(display[provider], text,
                          "%s is catalogued but missing from the about page" % provider)
            self.assertIn(
                "<strong>%s</strong></td><td class=\"mono\">%d</td>"
                % (display[provider], len(scopes)), text,
                "%s scope count on the about page is stale" % provider)

    def test_pricing_does_not_understate_provider_count(self):
        n_prov, _ = live()
        text = (SITE / "pricing.html").read_text()
        self.assertNotIn("all five providers", text)
        self.assertIn("twelve providers" if n_prov == 12 else str(n_prov), text)


class NoEmDashes(unittest.TestCase):
    """Removed deliberately across the site; easy to reintroduce by hand."""

    def test_no_page_contains_an_em_dash(self):
        for page in sorted(SITE.glob("*.html")):
            self.assertNotIn("—", page.read_text(), "%s has an em dash" % page.name)


if __name__ == "__main__":
    unittest.main()
