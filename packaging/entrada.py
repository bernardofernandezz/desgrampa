"""Ponto de entrada do executável único (PyInstaller)."""

import sys

from desgrampa.cli import main

if __name__ == "__main__":
    sys.exit(main())
