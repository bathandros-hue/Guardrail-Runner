# Guardrail Runner

Execute pre-authored JSON plans through allowlisted tools, with step budgets, declared dependencies, path containment, and content-hash audit records. It is a deterministic executor for AI-agent-produced plans, **not an autonomous LLM or an impenetrable sandbox**.

## Quickstart

    python -m unittest discover -s tests -v
    python -m guardrail.cli --root examples/workspace --plan examples/plan.json

Python 3.10+; no runtime dependencies. The CLI refuses file writes by default. To permit writes inside the selected root, explicitly supply --allow-write.

## Safety design

- Only named, built-in tools can execute; arbitrary shell commands cannot.
- All file paths are resolved against an existing root, including symlink traversal.
- JSON plan dependencies must point to earlier steps.
- Only explicitly declared dependencies can be interpolated using $ref:step_id.
- Policy limits steps and file size; write is not enabled by default.
- Audit events include SHA-256 hashes of arguments and outputs, but not full arguments.
- First error stops execution.

## Threat model / limitations

Not a security boundary against malicious code running in the same Python process, nor a defense against concurrency races, hard links, filesystem permission mistakes, or an attacker controlling the root directory. There is no natural-language planning or LLM integration. For untrusted hostile agents, execute inside additional OS/container sandboxing with minimal filesystem privileges.

## GitHub topics

ai-agents, tool-use, workflow-engine, security, audit-log, python

## License

MIT; see LICENSE.
