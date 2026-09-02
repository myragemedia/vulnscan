"""Central configuration for the scanner console.

Values are read from environment variables so the same code deploys unchanged
across dev, systemd and Docker. See .env.example for the full list.
"""
import os
from pathlib import Path


def _env_bool(name: str, default: bool = False) -> bool:
    return os.getenv(name, str(default)).strip().lower() in ("1", "true", "yes", "on")


BASE_DIR = Path(__file__).resolve().parent
FRONTEND_DIR = BASE_DIR.parent / "frontend"

# Where the SQLite database lives. Override with DATA_DIR for a Docker volume
# or a dedicated data partition on a server.
DATA_DIR = Path(os.getenv("DATA_DIR", str(BASE_DIR.parent / "data")))
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / "vulnscan.db"

# Severity ordering — drives report sorting and UI colour coding.
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

# Safety guard rail. Scans are only permitted against targets that resolve
# inside these ranges unless ALLOW_EXTERNAL is explicitly enabled. This keeps
# the tool pointed at networks you are authorised to assess.
ALLOW_EXTERNAL = _env_bool("ALLOW_EXTERNAL", False)

PRIVATE_CIDRS = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.0/8",
]

# Add authorised ranges without editing code, e.g.
#   EXTRA_SCOPE_CIDRS="203.0.113.0/24,198.51.100.7/32"
_extra = os.getenv("EXTRA_SCOPE_CIDRS", "").strip()
if _extra:
    PRIVATE_CIDRS += [c.strip() for c in _extra.split(",") if c.strip()]

# Cap on concurrent running scans so a host isn't overwhelmed.
MAX_CONCURRENT_SCANS = int(os.getenv("MAX_CONCURRENT_SCANS", "4"))
