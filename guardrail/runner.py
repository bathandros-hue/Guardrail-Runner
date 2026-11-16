"""Execute a constrained JSON plan with explicit policy and provenance."""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


READ_TOOLS = ("read_text", "list_files", "count_words", "find_lines")
ALL_TOOLS = READ_TOOLS + ("write_text",)


def digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, default=str).encode()).hexdigest()


@dataclass(frozen=True)
class Policy:
    root: Path
    allowed_tools: tuple[str, ...] = READ_TOOLS
    max_steps: int = 12
    max_read_bytes: int = 100_000
    max_write_bytes: int = 20_000

    def __post_init__(self) -> None:
        if self.max_steps < 1 or self.max_read_bytes < 1 or self.max_write_bytes < 1:
            raise ValueError("All policy limits must be positive")
        if set(self.allowed_tools) - set(ALL_TOOLS):
            raise ValueError("Unknown tool in allowlist")
        if not self.root.is_dir():
            raise ValueError("Root must be an existing directory")


@dataclass
class RunResult:
    outputs: dict[str, Any] = field(default_factory=dict)
    audit: list[dict[str, Any]] = field(default_factory=list)
    error: str | None = None

    @property
    def completed(self) -> bool:
        return self.error is None


class Runner:
    def __init__(self, policy: Policy):
        self.policy = policy
        self.root = policy.root.resolve()

    def _path(self, relative: str) -> Path:
        if not isinstance(relative, str):
            raise ValueError("Path must be a string")
        given = Path(relative)
        if given.is_absolute():
            raise ValueError("Absolute paths are forbidden")
        resolved = (self.root / given).resolve()
        if not resolved.is_relative_to(self.root):
            raise ValueError("Path escapes workspace root")
        return resolved

    @staticmethod
    def _validate(plan: list[dict[str, Any]], max_steps: int) -> list[dict[str, Any]]:
        if not isinstance(plan, list) or len(plan) > max_steps:
            raise ValueError("Plan must be a list within the step budget")
        ids: set[str] = set()
        for step in plan:
            if not isinstance(step, dict):
                raise ValueError("Steps must be objects")
            sid = step.get("id")
            if not isinstance(sid, str) or not sid.isidentifier() or sid in ids:
                raise ValueError("Each step needs a unique identifier")
            ids.add(sid)
            if not isinstance(step.get("tool"), str) or not isinstance(step.get("args", {}), dict):
                raise ValueError("Invalid tool or args")
            dependencies = step.get("depends_on", [])
            if not isinstance(dependencies, list) or any(
                not isinstance(dep, str) or dep not in ids - {sid} for dep in dependencies
            ):
                raise ValueError("Dependencies must refer to earlier steps")
        return plan

    def _resolve_args(self, value: Any, outputs: dict[str, Any],
                      allowed_refs: list[str]) -> Any:
        if isinstance(value, str) and value.startswith("$ref:"):
            ref = value[5:]
            if ref not in allowed_refs or ref not in outputs:
                raise ValueError("Reference is not an explicit completed dependency")
            return outputs[ref]
        if isinstance(value, list):
            return [self._resolve_args(v, outputs, allowed_refs) for v in value]
        if isinstance(value, dict):
            return {k: self._resolve_args(v, outputs, allowed_refs) for k, v in value.items()}
        return value

    def _execute(self, tool: str, args: dict[str, Any]) -> Any:
        if tool not in self.policy.allowed_tools:
            raise PermissionError(f"Tool forbidden by policy: {tool}")
        if tool == "count_words":
            txt = args["text"]
            if not isinstance(txt, str):
                raise ValueError("text must be a string")
            return {"words": len(txt.split()), "characters": len(txt)}
        if tool == "list_files":
            directory = self._path(args.get("path", "."))
            if not directory.is_dir():
                raise ValueError("Target directory does not exist")
            return sorted(
                x.relative_to(self.root).as_posix()
                for x in directory.iterdir()
                if x.is_file() and x.resolve().is_relative_to(self.root)
            )
        path = self._path(args["path"])
        if tool == "write_text":
            text = args["text"]
            if not isinstance(text, str):
                raise ValueError("text must be a string")
            if len(text.encode("utf-8")) > self.policy.max_write_bytes:
                raise ValueError("Write exceeds byte limit")
            if not path.parent.is_dir():
                raise ValueError("Destination parent must exist")
            path.write_text(text, encoding="utf-8")
            return {"path": path.relative_to(self.root).as_posix(), "bytes": len(text.encode("utf-8"))}
        if not path.is_file():
            raise ValueError("Target file does not exist")
        if path.stat().st_size > self.policy.max_read_bytes:
            raise ValueError("Read exceeds byte limit")
        text = path.read_text(encoding="utf-8")
        if tool == "read_text":
            return text
        if tool == "find_lines":
            needle = args["needle"]
            if not isinstance(needle, str) or not needle:
                raise ValueError("needle must be nonempty text")
            return [
                {"line": i, "text": line}
                for i, line in enumerate(text.splitlines(), 1)
                if needle.casefold() in line.casefold()
            ]
        raise ValueError(f"Unknown tool: {tool}")

    def run(self, plan: list[dict[str, Any]]) -> RunResult:
        result = RunResult()
        try:
            steps = self._validate(plan, self.policy.max_steps)
        except (ValueError, TypeError) as exc:
            result.error = str(exc)
            return result
        for step in steps:
            sid = step["id"]
            record: dict[str, Any] = {
                "id": sid, "tool": step["tool"], "args_sha256": digest(step.get("args", {}))
            }
            try:
                args = self._resolve_args(
                    step.get("args", {}), result.outputs, step.get("depends_on", [])
                )
                output = self._execute(step["tool"], args)
                result.outputs[sid] = output
                record.update({"status": "ok", "result_sha256": digest(output)})
            except (ValueError, PermissionError, KeyError, OSError, UnicodeError, TypeError) as exc:
                record.update({"status": "error", "error": str(exc)})
                result.error = f"{sid}: {exc}"
                result.audit.append(record)
                break
            result.audit.append(record)
        return result
