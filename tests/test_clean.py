"""Secret detection and masking in local transcripts.

The dangerous failure here is not missing a secret -- it is masking something
that was never one, because the file being rewritten is the user's own agent
history and a bad replacement is silent corruption.
"""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ranwhat.clean import find_secrets, scan, scan_file


def n(text):
    return len(find_secrets(text))


class Detection(unittest.TestCase):

    def test_secret_shaped_values(self):
        self.assertEqual(n("STRIPE=sk_live_51HxAbCdEfGhIjKlMnOpQr"), 1)
        self.assertEqual(n("AWS=AKIAIOSFODNN7REALKEY"), 1)
        self.assertEqual(n("JWT_ACCESS_SECRET=8f3a9c2e1b7d4f6a0c5e8b2d7f1a4c9e"), 1)

    def test_connection_string_password(self):
        self.assertEqual(n("DATABASE_URL=postgresql://admin:sup3rS3cretPw@db:5432/a"), 1)

    def test_password_inside_a_url_is_not_reported_twice(self):
        """It is already covered by the URL that contains it."""
        found = find_secrets("DATABASE_URL=postgresql://u:pa55word11@h:5432/d")
        self.assertEqual(len(found), 1)

    def test_ordinary_config_is_left_alone(self):
        for text in ("NODE_ENV=production", "PORT=3100",
                     "NEXT_PUBLIC_URL=https://example.com",
                     "LOG_LEVEL=debug"):
            self.assertEqual(n(text), 0, text)

    def test_placeholders_are_not_secrets(self):
        for text in ("API_KEY=your-api-key-here", "TOKEN=replace-with-your-token",
                     "PASSWORD=insert_password_here", "SECRET=enter-your-secret",
                     "JWT_SECRET=changeme", "DATABASE_URL=<redacted>",
                     "KEY=xxxxxxxxxx", "SECRET=${MY_SECRET}"):
            self.assertEqual(n(text), 0, text)

    def test_short_values_are_ignored(self):
        self.assertEqual(n("PASSWORD=abc"), 0)


def _transcript(body):
    root = tempfile.mkdtemp(prefix="clean-t-")
    d = os.path.join(root, "proj")
    os.makedirs(d)
    path = os.path.join(d, "s.jsonl")
    with open(path, "w") as fh:
        fh.write(json.dumps({"type": "user", "message": {"content": [
            {"type": "tool_result", "content": body}]}}) + "\n")
    return root, path


class Masking(unittest.TestCase):

    BODY = ("DATABASE_URL=postgresql://admin:sup3rS3cretPw@db:5432/app\n"
            "JWT_ACCESS_SECRET=8f3a9c2e1b7d4f6a0c5e8b2d7f1a4c9e\n"
            "NODE_ENV=production\n")

    def test_dry_run_changes_nothing(self):
        root, path = _transcript(self.BODY)
        before = open(path).read()
        findings, scanned, changed = scan(root=root, apply=False)
        self.assertEqual(len(findings), 2)
        self.assertEqual(changed, [])
        self.assertEqual(open(path).read(), before)

    def test_apply_masks_and_leaves_valid_json(self):
        root, path = _transcript(self.BODY)
        scan(root=root, apply=True)
        for line in open(path):
            if line.strip():
                json.loads(line)          # must still parse
        text = open(path).read()
        self.assertNotIn("sup3rS3cretPw", text)
        self.assertNotIn("8f3a9c2e1b7d4f6a0c5e8b2d7f1a4c9e", text)
        self.assertIn("NODE_ENV=production", text)
        self.assertIn("ranwhat:redacted:", text)

    def test_a_backup_is_written_before_changing_anything(self):
        from ranwhat.clean import BACKUP_ROOT
        root, path = _transcript(self.BODY)
        scan(root=root, apply=True)
        hits = []
        for base, _dirs, files in os.walk(BACKUP_ROOT):
            for f in files:
                if f == "s.jsonl":
                    hits.append(os.path.join(base, f))
        self.assertTrue(hits, "no backup was written")
        self.assertIn("sup3rS3cretPw", open(sorted(hits)[-1]).read())

    def test_running_twice_is_a_no_op(self):
        """A masked value must not be treated as a new secret to mask."""
        root, path = _transcript(self.BODY)
        scan(root=root, apply=True)
        after_first = open(path).read()
        findings, _scanned, changed = scan(root=root, apply=True)
        self.assertEqual(findings, {})
        self.assertEqual(changed, [])
        self.assertEqual(open(path).read(), after_first)

    def test_transcript_without_secrets_is_untouched(self):
        root, path = _transcript("NODE_ENV=production\nPORT=3100\n")
        before = open(path).read()
        findings, _s, changed = scan(root=root, apply=True)
        self.assertEqual(findings, {})
        self.assertEqual(changed, [])
        self.assertEqual(open(path).read(), before)


if __name__ == "__main__":
    unittest.main(verbosity=2)
