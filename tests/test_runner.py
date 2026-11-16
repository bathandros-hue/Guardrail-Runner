import tempfile
import unittest
from pathlib import Path

from guardrail import Policy, Runner


class TestRunner(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / "doc.txt").write_text("two word\nAgent workflow\n")

    def test_read_then_count(self):
        run = Runner(Policy(self.root)).run([
            {"id": "read", "tool": "read_text", "args": {"path": "doc.txt"}},
            {"id": "count", "tool": "count_words", "depends_on": ["read"],
             "args": {"text": "$ref:read"}},
        ])
        self.assertTrue(run.completed)
        self.assertEqual(run.outputs["count"]["words"], 4)
        self.assertEqual(len(run.audit), 2)
        self.assertEqual(len(run.audit[0]["args_sha256"]), 64)

    def test_forbidden_write(self):
        result = Runner(Policy(self.root)).run([
            {"id": "write", "tool": "write_text", "args": {"path": "x.txt", "text": "hi"}}
        ])
        self.assertFalse(result.completed)
        self.assertFalse((self.root / "x.txt").exists())

    def test_explicit_write(self):
        policy = Policy(self.root, allowed_tools=("write_text",))
        result = Runner(policy).run([
            {"id": "write", "tool": "write_text", "args": {"path": "x.txt", "text": "hi"}}
        ])
        self.assertTrue(result.completed)
        self.assertEqual((self.root / "x.txt").read_text(), "hi")

    def test_path_traversal(self):
        runner = Runner(Policy(self.root))
        for bad in ("../outside.txt", "/etc/passwd"):
            result = runner.run([
                {"id": "escape", "tool": "read_text", "args": {"path": bad}}
            ])
            self.assertFalse(result.completed)

    def test_symlink_escape(self):
        (self.root / "link").symlink_to(Path(self.tmp.name).parent)
        result = Runner(Policy(self.root)).run([
            {"id": "escape", "tool": "list_files", "args": {"path": "link"}}
        ])
        self.assertFalse(result.completed)

    def test_dependency_and_budget(self):
        for plan in (
            [{"id": "bad", "tool": "count_words", "depends_on": ["missing"], "args": {"text": ""}}],
            [{"id": "same", "tool": "count_words", "args": {"text": ""}},
             {"id": "same", "tool": "count_words", "args": {"text": ""}}],
        ):
            self.assertFalse(Runner(Policy(self.root)).run(plan).completed)
        over = Runner(Policy(self.root, max_steps=1)).run([
            {"id": "a", "tool": "list_files"}, {"id": "b", "tool": "list_files"}
        ])
        self.assertFalse(over.completed)

    def test_unapproved_reference(self):
        result = Runner(Policy(self.root)).run([
            {"id": "first", "tool": "read_text", "args": {"path": "doc.txt"}},
            {"id": "second", "tool": "count_words", "args": {"text": "$ref:first"}},
        ])
        self.assertFalse(result.completed)

    def test_read_limit(self):
        result = Runner(Policy(self.root, max_read_bytes=1)).run([
            {"id": "read", "tool": "read_text", "args": {"path": "doc.txt"}}
        ])
        self.assertFalse(result.completed)


if __name__ == "__main__":
    unittest.main()
