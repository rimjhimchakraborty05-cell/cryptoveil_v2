"""Install dependencies only when their declared requirements change."""

import hashlib
import subprocess
import sys
from pathlib import Path

root = Path(__file__).resolve().parents[1]
if sys.version_info < (3, 11):  # noqa: UP036 - bootstrap can run before version validation
    raise SystemExit("CryptoVeil requires Python 3.11 or later")
files = [root / "requirements.txt", root / "requirements-core.txt"]
fingerprint = hashlib.sha256(b"".join(path.read_bytes() for path in files)).hexdigest()
stamp = Path(sys.prefix) / ".cryptoveil-requirements"
if not stamp.exists() or stamp.read_text() != fingerprint:
    subprocess.run(
        [sys.executable, "-m", "pip", "install", "-r", str(files[0])], cwd=root, check=True
    )
    stamp.write_text(fingerprint)
