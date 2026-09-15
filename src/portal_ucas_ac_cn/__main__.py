"""Allow ``python -m portal_ucas_ac_cn``."""
from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
