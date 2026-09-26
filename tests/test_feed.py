"""The feed must not be able to break the three things the tool promises:
that it works offline, that it sends nothing, and that a bad payload can
never reach a report."""
import json
import os
import shutil
import tempfile
import unittest

from ranwhat import catalog, feed


def _entry(label="X", authority="write", reversible=False,
           blast="data_egress", why="because"):
    return {"label": label, "authority": authority, "reversible": reversible,
            "blast": blast, "why": why}


def _doc(catalogue=None, version="2026.09.26"):
    cat = catalogue if catalogue is not None else {"acme": {"acme:delete": _entry()}}
    return {"schema": feed.SCHEMA, "version": version, "catalogue": cat,
            "digest": feed.digest(cat)}


class FeedHome(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self._old = os.environ.get("RANWHAT_HOME")
        os.environ["RANWHAT_HOME"] = self.dir
        catalog.reset_feed_cache()

    def tearDown(self):
        if self._old is None:
            os.environ.pop("RANWHAT_HOME", None)
        else:
            os.environ["RANWHAT_HOME"] = self._old
        shutil.rmtree(self.dir, ignore_errors=True)
        catalog.reset_feed_cache()


class Validation(FeedHome):
    def test_rejects_wrong_schema(self):
        d = _doc(); d["schema"] = 999
        with self.assertRaises(feed.FeedError):
            feed.validate(d)

    def test_rejects_missing_field(self):
        bad = _entry(); del bad["why"]
        with self.assertRaises(feed.FeedError):
            feed.validate(_doc({"acme": {"acme:x": bad}}))

    def test_rejects_tampered_catalogue(self):
        d = _doc()
        d["catalogue"]["acme"]["acme:delete"]["authority"] = "read"
        with self.assertRaises(feed.FeedError):
            feed.validate(d)

    def test_rejects_empty_catalogue(self):
        with self.assertRaises(feed.FeedError):
            feed.validate(_doc({}))


class Offline(FeedHome):
    def test_no_feed_means_no_feed_not_an_error(self):
        self.assertIsNone(feed.load())
        self.assertFalse(feed.status()["active"])

    def test_corrupt_cache_degrades_silently(self):
        os.makedirs(os.path.dirname(feed.feed_path()), exist_ok=True)
        with open(feed.feed_path(), "w") as fh:
            fh.write("{not json")
        self.assertIsNone(feed.load())

    def test_bundled_catalogue_still_resolves_without_a_feed(self):
        e = catalog.lookup("google", "https://www.googleapis.com/auth/gmail.send")
        self.assertTrue(e["known"])
        self.assertEqual(e["authority"], "write")


class Merging(FeedHome):
    def test_feed_adds_scopes_the_bundle_lacks(self):
        feed.save(_doc({"notion": {"notion:read_content": _entry("Read pages")}}))
        catalog.reset_feed_cache()
        e = catalog.lookup("notion", "notion:read_content")
        self.assertTrue(e["known"])
        self.assertEqual(e["label"], "Read pages")

    def test_feed_overrides_a_bundled_scope(self):
        scope = "https://www.googleapis.com/auth/gmail.send"
        feed.save(_doc({"google": {scope: _entry("Reclassified", "destructive")}}))
        catalog.reset_feed_cache()
        self.assertEqual(catalog.lookup("google", scope)["authority"], "destructive")

    def test_feed_cannot_remove_a_bundled_scope(self):
        """A feed that has not caught up must not delete local knowledge."""
        feed.save(_doc({"google": {"google:something_new": _entry()}}))
        catalog.reset_feed_cache()
        e = catalog.lookup("google", "https://www.googleapis.com/auth/gmail.send")
        self.assertTrue(e["known"], "bundled scope disappeared when a feed arrived")

    def test_narrow_scope_still_never_widened_to_a_wildcard(self):
        """The rule that makes reports trustworthy survives the feed."""
        feed.save(_doc({"aws": {"s3:*": _entry("All S3", "destructive")}}))
        catalog.reset_feed_cache()
        self.assertFalse(catalog.lookup("aws", "s3:ListBucket").get("known"))


class TokenHandling(FeedHome):
    def test_saved_token_is_not_world_readable(self):
        path = feed.save_token("tok_abc")
        self.assertEqual(oct(os.stat(path).st_mode & 0o777), oct(0o600))

    def test_environment_beats_the_file(self):
        feed.save_token("from_file")
        os.environ["RANWHAT_TOKEN"] = "from_env"
        try:
            self.assertEqual(feed.read_token(), "from_env")
        finally:
            os.environ.pop("RANWHAT_TOKEN", None)

    def test_no_token_is_not_an_error(self):
        self.assertIsNone(feed.read_token())


class SendsNothing(FeedHome):
    def test_request_carries_the_token_and_no_machine_detail(self):
        seen = {}

        class FakeResp:
            def read(self): return json.dumps(_doc()).encode()
            def __enter__(self): return self
            def __exit__(self, *a): return False

        import urllib.request
        real = urllib.request.urlopen

        def spy(req, *a, **kw):
            seen["url"] = req.full_url
            seen["headers"] = dict(req.header_items())
            seen["body"] = req.data
            return FakeResp()

        urllib.request.urlopen = spy
        try:
            feed.fetch("tok_xyz", url="https://example.invalid/v1/catalogue")
        finally:
            urllib.request.urlopen = real

        self.assertIsNone(seen["body"], "update sent a request body")
        values = " ".join(str(v) for v in seen["headers"].values())
        self.assertIn("Bearer tok_xyz", values)
        for leak in (os.uname().nodename, os.path.expanduser("~")):
            self.assertNotIn(leak, values)
        self.assertNotIn("?", seen["url"], "no query string, so nothing smuggled in one")


if __name__ == "__main__":
    unittest.main()
