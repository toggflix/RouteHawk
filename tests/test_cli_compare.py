import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from routehawk.cli import main


class CliCompareTests(unittest.TestCase):
    def test_compare_writes_json_diff(self):
        with TemporaryDirectory() as temporary:
            base_path = Path(temporary) / "base.json"
            head_path = Path(temporary) / "head.json"
            output_path = Path(temporary) / "diff.json"
            base_path.write_text(
                json.dumps(
                    {
                        "endpoints": [
                            {"method": "GET", "normalized_path": "/api/users/{id}", "risk_score": 70},
                            {"method": "GET", "normalized_path": "/api/orders/{id}", "risk_score": 65},
                        ]
                    }
                ),
                encoding="utf-8",
            )
            head_path.write_text(
                json.dumps(
                    {
                        "endpoints": [
                            {"method": "GET", "normalized_path": "/api/users/{id}", "risk_score": 80},
                            {"method": "GET", "normalized_path": "/api/billing/{id}", "risk_score": 90},
                        ]
                    }
                ),
                encoding="utf-8",
            )

            exit_code = main(
                [
                    "compare",
                    "--base",
                    str(base_path),
                    "--head",
                    str(head_path),
                    "--out",
                    str(output_path),
                ]
            )

            payload = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(exit_code, 0)
            self.assertEqual(payload["summary"]["new_count"], 1)
            self.assertEqual(payload["summary"]["removed_count"], 1)
            self.assertEqual(payload["summary"]["changed_count"], 1)
            self.assertEqual(payload["summary"]["unchanged_count"], 0)

    def test_compare_writes_markdown_diff(self):
        with TemporaryDirectory() as temporary:
            base_path = Path(temporary) / "base.json"
            head_path = Path(temporary) / "head.json"
            output_path = Path(temporary) / "diff.md"
            base_path.write_text(json.dumps({"endpoints": []}), encoding="utf-8")
            head_path.write_text(json.dumps({"endpoints": []}), encoding="utf-8")

            exit_code = main(
                [
                    "compare",
                    "--base",
                    str(base_path),
                    "--head",
                    str(head_path),
                    "--out",
                    str(output_path),
                ]
            )

            text = output_path.read_text(encoding="utf-8")
            self.assertEqual(exit_code, 0)
            self.assertIn("# RouteHawk Diff Report", text)
            self.assertIn("## Summary", text)
            self.assertIn("## New endpoints", text)

    def test_compare_requires_existing_files(self):
        with TemporaryDirectory() as temporary:
            base_path = Path(temporary) / "missing-base.json"
            head_path = Path(temporary) / "missing-head.json"

            with self.assertRaises(SystemExit):
                main(
                    [
                        "compare",
                        "--base",
                        str(base_path),
                        "--head",
                        str(head_path),
                    ]
                )


if __name__ == "__main__":
    unittest.main()
