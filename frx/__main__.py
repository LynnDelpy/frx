"""Enable `python -m frx ...`.

The offline sandbox re-executes the pass as `python -m frx <args>` inside a
network namespace (see frx.engine.sandbox), so this entry point must exist and
behave identically to the `frx` console script.
"""

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
