"""Make the in-repo proxy package importable without an editable install."""

from __future__ import annotations

import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parents[1] / "proxy" / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))
