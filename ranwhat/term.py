"""Terminal presentation: width, rules and colour.

Width was hardcoded at 62 for rules and 70 for prose, which is unreadable in
both directions. On a narrow window the output wrapped twice, once by this
tool and again by the terminal, producing ragged half-lines. On a wide one it
used a third of the screen.

Colour honours NO_COLOR (no-color.org) and only engages on a tty, so piping to
a file or a pager still produces plain text.
"""
from __future__ import annotations

import os
import shutil
import sys

# Below this, indentation and bars cost more than they convey.
MIN_WIDTH = 46
# Prose stops being readable past roughly this many characters per line, so a
# wide terminal gets whitespace rather than very long measures.
MAX_WIDTH = 96

BRAND = (0xE9, 0x84, 0x71)


def width(stream=None):
    """Usable columns, clamped to something readable."""
    stream = stream or sys.stdout
    try:
        cols = shutil.get_terminal_size().columns
    except Exception:
        cols = 80
    if os.environ.get("RANWHAT_WIDTH"):
        try:
            cols = int(os.environ["RANWHAT_WIDTH"])
        except ValueError:
            pass
    return max(MIN_WIDTH, min(MAX_WIDTH, cols - 2))


def rule(char="─", stream=None):
    return "  " + char * (width(stream) - 2)


def _colour_depth(stream=None):
    """0 = none, 8 = basic ANSI, 24 = truecolour."""
    stream = stream or sys.stdout
    if os.environ.get("NO_COLOR") is not None:
        return 0
    if not hasattr(stream, "isatty") or not stream.isatty():
        return 0
    if os.environ.get("TERM") == "dumb":
        return 0
    ct = os.environ.get("COLORTERM", "").lower()
    if "truecolor" in ct or "24bit" in ct:
        return 24
    return 8


def brand(s, stream=None):
    """The wordmark colour, in truecolour where the terminal supports it.

    Falls back to plain ANSI rather than approximating: a wrong-looking orange
    is worse than no orange, and this is decoration, not information.
    """
    depth = _colour_depth(stream)
    if depth == 24:
        r, g, b = BRAND
        return "\033[38;2;%d;%d;%dm%s\033[0m" % (r, g, b, s)
    if depth == 8:
        return "\033[33m%s\033[0m" % s
    return s


def wrap(text, indent="  ", stream=None):
    """Fold prose to the terminal, without importing textwrap for one job."""
    limit = width(stream) - len(indent)
    out, line = [], ""
    for word in text.split():
        if line and len(line) + 1 + len(word) > limit:
            out.append(indent + line)
            line = word
        else:
            line = word if not line else line + " " + word
    if line:
        out.append(indent + line)
    return out
