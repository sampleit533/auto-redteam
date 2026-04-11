#!/usr/bin/env python3
"""Generate a minimal valid evaluation.json stub for dry-run / skipped evaluation."""
import json
import os
import pathlib
from datetime import datetime, timezone

stub = {
    "run_id": os.environ.get("GITHUB_RUN_ID", "local"),
    "evaluated_at": datetime.now(timezone.utc).isoformat(),
    "summary": {
        "scenarios_evaluated": 0,
        "total_detection_checks": 0,
        "passed": 0,
        "overall_coverage_pct": 0.0,
    },
    "scenarios": [],
}

pathlib.Path("artifacts").mkdir(exist_ok=True)
with open("artifacts/evaluation.json", "w") as f:
    json.dump(stub, f, indent=2)
print("Created evaluation stub (dry-run or evaluation skipped)")
