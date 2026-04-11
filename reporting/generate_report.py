#!/usr/bin/env python3
"""
Report generator — renders HTML report from evaluation.json using Jinja2.

Usage:
    python generate_report.py \
        --evaluation artifacts/evaluation.json \
        --template reporting/templates/report.html.j2 \
        --out artifacts/report.html
"""

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader


def main():
    parser = argparse.ArgumentParser(description="auto-redteam report generator")
    parser.add_argument("--evaluation", default="artifacts/evaluation.json")
    parser.add_argument("--template", default="reporting/templates/report.html.j2")
    parser.add_argument("--out", default="artifacts/report.html")
    args = parser.parse_args()

    with open(args.evaluation) as f:
        data = json.load(f)

    template_path = Path(args.template)
    env = Environment(loader=FileSystemLoader(str(template_path.parent)))
    template = env.get_template(template_path.name)

    html = template.render(
        data=data,
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
    )

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(html)
    print(f"[REPORT] Report written to {out_path}")


if __name__ == "__main__":
    main()
