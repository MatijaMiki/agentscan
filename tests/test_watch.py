"""Precision tests for the local watcher.

The failure mode that matters is false positives. A watcher that fires on a
script *containing* a dangerous string, or on a grep searching *for* one,
gets muted within a day -- and a muted watcher records nothing anyone reads.
Every case here is a real pattern that tripped the naive implementation.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agentscan import watch


def fires(command):
    return bool(watch.evaluate("Bash", {"command": command})[0])


class NoFalsePositives(unittest.TestCase):
    """Things that mention a dangerous action without performing one."""

    def test_searching_for_a_pattern(self):
        self.assertFalse(fires('grep -rn ".aws/credentials" .'))
        self.assertFalse(fires('rg "rm -rf" src/'))
        self.assertFalse(fires('find . -name "*.env"'))

    def test_foreign_interpreter_source(self):
        self.assertFalse(fires('python3 -c "print(\'rm -rf /\')"'))
        self.assertFalse(fires('node -e "x=\'git push --force\'"'))
        self.assertFalse(fires("sudo python3 -c 'rm -rf /'"))

    def test_interpreter_payload_containing_shell_operators(self):
        """The payload has its own ';' and '|', which must not split it."""
        self.assertFalse(fires('python3 -c "x=\'cat .env\'; y=\\"rm -rf\\""'))

    def test_heredoc_body_is_data_not_commands(self):
        self.assertFalse(fires("python3 - <<'EOF'\nrm -rf /\nEOF"))
        self.assertFalse(fires("cat > f.sh <<'EOF'\nrm -rf /\nEOF"))

    def test_file_content_is_not_an_action(self):
        self.assertEqual(watch.evaluate("Write", {"file_path": "a.sh",
                                                  "content": "rm -rf /"})[0], [])
        self.assertEqual(watch.evaluate("Edit", {"file_path": "a.sh",
                                                 "new_string": "npm publish"})[0], [])


class NoFalseNegatives(unittest.TestCase):
    """Things that really do perform the action."""

    def test_plain_destructive_command(self):
        self.assertTrue(fires("rm -rf build/"))
        self.assertTrue(fires("cat ~/.aws/credentials"))

    def test_shell_interpreter_payload_is_recursed_into(self):
        """bash -c really does execute shell, unlike python -c."""
        self.assertTrue(fires("bash -c 'rm -rf /tmp/x'"))

    def test_later_segment_of_a_chain(self):
        self.assertTrue(fires("echo hi && rm -rf dist"))
        self.assertTrue(fires("python3 -c 'print(1)' && rm -rf dist"))

    def test_find_with_an_action_is_not_a_search(self):
        self.assertTrue(fires('find . -name "*.tmp" -delete'))

    def test_secret_literal_fires_even_in_a_search(self):
        """A live key in a grep pattern is still a leaked key."""
        self.assertTrue(fires('grep -r "AKIA1234567890ABCDEF" .'))


class Evidence(unittest.TestCase):

    def test_evidence_includes_the_target(self):
        """'rm -rf' alone is unjudgeable; the target is the whole point."""
        hits, _ = watch.evaluate("Bash", {"command": "rm -rf /tmp/scratch-dir"})
        self.assertIn("scratch-dir", hits[0]["evidence"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
