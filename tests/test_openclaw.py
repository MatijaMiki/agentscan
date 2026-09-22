"""OpenClaw source adapter.

OpenClaw's transcript schema is not documented -- only that it is SQLite,
append-only and tree-structured. Hardcoding table and column names from a
guess would break on the next release, so the adapter discovers the schema
at runtime and recognises tool calls by shape. These tests use deliberately
unfamiliar table and column names to keep that honest.
"""
import json
import os
import sqlite3
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agentscan import watch


def make_db(rows, table="weird_entry_log", body="payload_blob",
            time_col="createdAt"):
    root = tempfile.mkdtemp(prefix="oc-test-")
    path = os.path.join(root, "agents", "a1", "agent", "openclaw-agent.sqlite")
    os.makedirs(os.path.dirname(path))
    conn = sqlite3.connect(path)
    conn.execute('CREATE TABLE "%s" (id TEXT, parentId TEXT, "%s" TEXT, "%s" INTEGER)'
                 % (table, body, time_col))
    conn.executemany('INSERT INTO "%s" VALUES (?,?,?,?)' % table, rows)
    conn.commit()
    conn.close()
    return root


def tool_use(command, name="bash"):
    return json.dumps({"content": [{"type": "tool_use", "name": name,
                                    "input": {"command": command}}]})


class SchemaDiscovery(unittest.TestCase):

    def test_finds_database_and_unfamiliar_schema(self):
        root = make_db([("1", None, tool_use("rm -rf ~/old"), 1758550000)])
        self.assertEqual(len(watch.openclaw_databases(root)), 1)
        records, n = watch.scan_openclaw(state_dir=root)
        self.assertEqual(n, 1)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["source"], "openclaw")

    def test_extracts_timestamp_from_discovered_column(self):
        root = make_db([("1", None, tool_use("rm -rf ~/old"), 1758550000)],
                       time_col="ts")
        records, _ = watch.scan_openclaw(state_dir=root)
        self.assertTrue(records[0]["timestamp"].startswith("20"))

    def test_missing_state_dir_is_not_an_error(self):
        records, n = watch.scan_openclaw(state_dir="/nonexistent/path")
        self.assertEqual((records, n), ([], 0))


class ToolCallShapes(unittest.TestCase):

    def test_anthropic_tool_use(self):
        self.assertEqual(
            watch._find_tool_calls({"type": "tool_use", "name": "bash",
                                    "input": {"command": "x"}}),
            [("bash", {"command": "x"})])

    def test_openai_function_call_is_not_double_counted(self):
        found = watch._find_tool_calls(
            {"function": {"name": "shell",
                          "arguments": '{"command": "npm publish"}'}})
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0], ("shell", {"command": "npm publish"}))

    def test_alternate_key_names(self):
        self.assertEqual(
            watch._find_tool_calls({"toolName": "exec", "args": {"command": "x"}}),
            [("exec", {"command": "x"})])

    def test_nested_and_json_encoded_strings(self):
        found = watch._find_tool_calls(
            {"rows": [{"blob": json.dumps({"tool": "bash",
                                           "params": {"command": "x"}})}]})
        self.assertIn(("bash", {"command": "x"}), found)


class PrecisionCarriesOver(unittest.TestCase):
    """The same suppression rules must apply regardless of source."""

    def test_search_and_prose_are_not_flagged(self):
        root = make_db([
            ("1", None, tool_use("grep -rn 'rm -rf' ./src"), 1758550000),
            ("2", "1", json.dumps({"content": [{"type": "text",
                                                "text": "talking about rm -rf"}]}),
             1758550001),
            ("3", "2", tool_use("rm -rf ~/real-target"), 1758550002),
        ])
        records, _ = watch.scan_openclaw(state_dir=root)
        self.assertEqual(len(records), 1)
        self.assertIn("real-target", records[0]["hits"][0]["evidence"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
