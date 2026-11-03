"""Module execution entry point (`python -m aisvs_scanner`)."""
import sys
from .cli import main

if __name__ == "__main__":
    sys.exit(main())
