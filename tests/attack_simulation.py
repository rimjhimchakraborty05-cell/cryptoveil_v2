"""Run the isolated evidence-integrity demonstration without a live server."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from agent.forensics.demo import demonstrate_integrity

if __name__ == "__main__":
    result = demonstrate_integrity()
    print(json.dumps(result, indent=2))
    assert [check["verified"] for check in result["checks"]] == [True, False, False, False]
