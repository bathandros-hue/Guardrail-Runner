"""Run pre-authored JSON tool plans; does not call or simulate an LLM."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from .runner import Policy, Runner, READ_TOOLS


def main() -> None:
    parser = argparse.ArgumentParser(description="Policy-bounded JSON workflow runner")
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--allow-write", action="store_true")
    parser.add_argument("--max-steps", type=int, default=12)
    args = parser.parse_args()
    policy = Policy(
        args.root, allowed_tools=(*READ_TOOLS, "write_text") if args.allow_write else READ_TOOLS,
        max_steps=args.max_steps,
    )
    plan = json.loads(args.plan.read_text(encoding="utf-8"))
    outcome = Runner(policy).run(plan)
    print(json.dumps({
        "completed": outcome.completed,
        "outputs": outcome.outputs,
        "audit": outcome.audit,
        "error": outcome.error,
    }, indent=2))
    if not outcome.completed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
