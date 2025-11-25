"""Allow running as python -m shai_hulud_scanner."""

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
