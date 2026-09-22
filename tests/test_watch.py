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
        self.assertTrue(fires("rm -rf ~/Documents/archive"))
        self.assertTrue(fires("cat ~/.aws/credentials"))

    def test_shell_interpreter_payload_is_recursed_into(self):
        """bash -c really does execute shell, unlike python -c."""
        self.assertTrue(fires("bash -c 'rm -rf ~/notes'"))

    def test_later_segment_of_a_chain(self):
        self.assertTrue(fires("echo hi && rm -rf ~/photos"))
        self.assertTrue(fires("python3 -c 'print(1)' && rm -rf ~/photos"))

    def test_find_with_an_action_is_not_a_search(self):
        self.assertTrue(fires('find . -name "*.tmp" -delete'))

    def test_secret_literal_fires_even_in_a_search(self):
        """A live key in a grep pattern is still a leaked key."""
        self.assertTrue(fires('grep -r "AKIA1234567890ABCDEF" .'))


class Evidence(unittest.TestCase):

    def test_evidence_includes_the_target(self):
        """'rm -rf' alone is unjudgeable; the target is the whole point."""
        hits, _ = watch.evaluate("Bash", {"command": "rm -rf ~/client-archive"})
        self.assertIn("client-archive", hits[0]["evidence"])


if __name__ == "__main__":
    unittest.main(verbosity=2)


class DeletionSeverityFollowsTheTarget(unittest.TestCase):
    """The verb alone is not enough signal.

    On a real machine 11 of 15 findings were `rm -rf` against build and temp
    directories. All true, none worth an alert -- and a report that is 73%
    noise gets muted exactly as fast as one full of false positives.
    """

    def severity(self, command):
        hits, _ = watch.evaluate("Bash", {"command": command})
        return hits[0]["severity"] if hits else None

    def test_build_and_temp_directories_are_not_surfaced(self):
        for cmd in ("rm -rf build", "rm -rf dist", "rm -rf target",
                    "rm -rf node_modules && npm install",
                    "rm -rf /tmp/scratch", "rm -rf .venv",
                    "rm -rf __pycache__", "rm -rf build dist target"):
            self.assertIsNone(self.severity(cmd), cmd)

    def test_real_paths_still_surface(self):
        for cmd in ("rm -rf ~/Documents", 'rm -rf "$HOME/Desktop/work"',
                    "rm -rf /srv/uploads"):
            self.assertEqual(self.severity(cmd), watch.HIGH, cmd)

    def test_catastrophic_targets_escalate(self):
        for cmd in ("rm -rf /", "rm -rf / --no-preserve-root", "rm -rf ~",
                    "rm -rf $HOME", "rm -rf /usr", "rm -rf /etc"):
            self.assertEqual(self.severity(cmd), watch.CRITICAL, cmd)

    def test_root_is_not_lost_to_slash_trimming(self):
        """"/".rstrip("/") is the empty string, which silently dropped the one
        target that matters most."""
        self.assertEqual(self.severity("rm -rf /"), watch.CRITICAL)

    def test_a_mixed_deletion_is_judged_by_its_worst_target(self):
        self.assertEqual(self.severity("rm -rf /tmp/x ~/important"), watch.HIGH)

    def test_redirections_are_not_deletion_targets(self):
        """`2>/dev/null` trailing an rm is not a path being removed. Treating
        it as one made every quietened cleanup look like a real deletion."""
        self.assertEqual(watch._rm_targets("rm -rf build 2>/dev/null"), ["build"])
        self.assertEqual(watch._rm_targets("rm -rf build > /dev/null"), ["build"])
        self.assertIsNone(self.severity("rm -rf build dist 2>/dev/null"))

    def test_generated_directories_matched_by_suffix(self):
        self.assertIsNone(self.severity("rm -rf agentscan.egg-info"))
        self.assertIsNone(self.severity("rm -rf build foo.egg-info 2>/dev/null"))


class ProseIsNotACommand(unittest.TestCase):

    def test_description_field_is_ignored(self):
        """The Bash tool carries a human-readable description. One that says
        "clean up the rm -rf targets" is prose, not a deletion."""
        hits, _ = watch.evaluate("Bash", {
            "command": "ls -la",
            "description": "Get rule breakdown and rm -rf target distribution"})
        self.assertEqual(hits, [])
