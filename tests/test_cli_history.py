import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from routehawk.cli import main
from routehawk.storage.sqlite import record_scan


class CliHistoryTests(unittest.TestCase):
    def test_history_reads_sqlite_runs(self):
        with TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            routehawk_dir = workspace / ".routehawk"
            routehawk_dir.mkdir(parents=True, exist_ok=True)
            database_path = routehawk_dir / "routehawk.sqlite"
            output_path = workspace / "history.json"
            metadata = {
                "run_id": "20260508-120001",
                "generated_at": "2026-05-08T12:00:01Z",
                "target": "http://localhost:8088",
                "scope": ["localhost"],
                "assets": 1,
                "javascript_files": 1,
                "metadata": 5,
                "endpoints": 9,
                "findings": 8,
                "high_risk": 4,
                "medium_risk": 0,
                "new_endpoints": 2,
                "removed_endpoints": 1,
                "changed_endpoints": 3,
            }
            record_scan(database_path, metadata, {"endpoints": []}, {"new_count": 2})

            exit_code = main(
                [
                    "history",
                    "--workspace",
                    str(workspace),
                    "--out",
                    str(output_path),
                ]
            )

            payload = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(exit_code, 0)
            self.assertEqual(payload["count"], 1)
            self.assertEqual(payload["runs"][0]["source"], "sqlite")
            self.assertEqual(payload["runs"][0]["target"], "http://localhost:8088")

    def test_history_falls_back_to_file_runs(self):
        with TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            run_dir = workspace / ".routehawk" / "runs" / "20260508-120002"
            run_dir.mkdir(parents=True, exist_ok=True)
            (run_dir / "summary.json").write_text(
                json.dumps(
                    {
                        "run_id": "20260508-120002",
                        "generated_at": "2026-05-08T12:00:02Z",
                        "target": "http://localhost:8088",
                        "scope": ["localhost"],
                        "endpoints": 7,
                        "findings": 5,
                        "high_risk": 2,
                        "new_endpoints": 1,
                        "removed_endpoints": 0,
                        "changed_endpoints": 1,
                    }
                ),
                encoding="utf-8",
            )
            output_path = workspace / "history.json"

            exit_code = main(
                [
                    "history",
                    "--workspace",
                    str(workspace),
                    "--out",
                    str(output_path),
                ]
            )

            payload = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(exit_code, 0)
            self.assertEqual(payload["count"], 1)
            self.assertEqual(payload["runs"][0]["source"], "files")
            self.assertEqual(payload["runs"][0]["run_id"], "20260508-120002")


if __name__ == "__main__":
    unittest.main()
