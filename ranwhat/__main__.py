"""Allow `python -m ranwhat` as well as the installed `ranwhat` script."""
import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
