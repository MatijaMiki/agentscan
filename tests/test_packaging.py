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

import ranwhat


def pyproject():
    with open(os.path.join(ROOT, "pyproject.toml")) as fh:
        return fh.read()


class Metadata(unittest.TestCase):

    def test_version_matches_package(self):
        declared = re.search(r'^version\s*=\s*"([^"]+)"', pyproject(),
                             re.M).group(1)
        self.assertEqual(declared, ranwhat.__version__)

    def test_console_script_target_is_importable(self):
        target = re.search(r'^ranwhat\s*=\s*"([^"]+)"', pyproject(),
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
        self.assertIn('ranwhat = ["demo/*.json"]', pyproject())
        self.assertTrue(os.path.isfile(
            os.path.join(ROOT, "ranwhat", "demo", "support-copilot.json")))

    def test_demo_loads_through_the_package(self):
        from ranwhat.cli import _bundled
        self.assertEqual(_bundled("support-copilot.json")["agent"],
                         "support-copilot")


if __name__ == "__main__":
    unittest.main(verbosity=2)


class SuggestedCommands(unittest.TestCase):
    """`uvx ranwhat` runs from a throwaway environment that is not on PATH.
    Telling that user to run `ranwhat demo` sends them to command-not-found,
    which is what the overview did on its first day."""

    def test_suggests_uvx_when_the_bare_command_is_not_on_path(self):
        import shutil as _shutil
        from ranwhat import cli
        real_which, real_argv = _shutil.which, sys.argv
        try:
            _shutil.which = lambda name: None          # nothing on PATH
            sys.argv = ["/tmp/uv-cache/archive/bin/ranwhat"]
            self.assertEqual(cli.invocation(), "uvx ranwhat")
        finally:
            _shutil.which, sys.argv = real_which, real_argv

    def test_suggests_the_bare_command_when_it_resolves_to_us(self):
        import shutil as _shutil
        from ranwhat import cli
        real_which, real_argv = _shutil.which, sys.argv
        try:
            _shutil.which = lambda name: __file__
            sys.argv = [__file__]
            self.assertEqual(cli.invocation(), "ranwhat")
        finally:
            _shutil.which, sys.argv = real_which, real_argv

    def test_overview_never_prints_a_command_the_reader_cannot_run(self):
        import io, contextlib, shutil as _shutil
        from ranwhat import cli
        real_which, real_argv = _shutil.which, sys.argv
        try:
            _shutil.which = lambda name: None
            sys.argv = ["/tmp/uv-cache/archive/bin/ranwhat"]
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                cli._overview(None)
            text = buf.getvalue()
        finally:
            _shutil.which, sys.argv = real_which, real_argv
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("ranwhat ") and not stripped.startswith("ranwhat  "):
                self.fail("overview told a uvx user to run %r" % stripped)
