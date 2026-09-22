"""Packaging metadata.

Old setuptools silently builds a wheel named UNKNOWN-0.0.0 when it cannot
read PEP 621 metadata, which installs without error and provides no command.
These check the declared metadata stays intact and in sync.
"""
import os
import re
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import agentscan


def pyproject():
    with open(os.path.join(ROOT, "pyproject.toml")) as fh:
        return fh.read()


class Metadata(unittest.TestCase):

    def test_version_matches_package(self):
        declared = re.search(r'^version\s*=\s*"([^"]+)"', pyproject(),
                             re.M).group(1)
        self.assertEqual(declared, agentscan.__version__)

    def test_console_script_target_is_importable(self):
        target = re.search(r'^agentscan\s*=\s*"([^"]+)"', pyproject(),
                           re.M).group(1)
        module, _, attr = target.partition(":")
        mod = __import__(module, fromlist=[attr])
        self.assertTrue(callable(getattr(mod, attr)))

    def test_no_runtime_dependencies(self):
        """This gets pointed at the user's own credentials. A dependency tree
        is something a reviewer has to audit before that is reasonable."""
        deps = re.search(r"^dependencies\s*=\s*\[(.*?)\]", pyproject(),
                         re.M | re.S).group(1).strip()
        self.assertEqual(deps, "")

    def test_bundled_demo_data_is_inside_the_package(self):
        """It previously installed to site-packages/demo/, a top-level
        directory that would collide with any other package shipping one."""
        self.assertIn('agentscan = ["demo/*.json"]', pyproject())
        self.assertTrue(os.path.isfile(
            os.path.join(ROOT, "agentscan", "demo", "support-copilot.json")))

    def test_demo_loads_through_the_package(self):
        from agentscan.cli import _bundled
        self.assertEqual(_bundled("support-copilot.json")["agent"],
                         "support-copilot")


if __name__ == "__main__":
    unittest.main(verbosity=2)
