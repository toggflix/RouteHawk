import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from routehawk.storage.sqlite import (
    fetch_scan_payload,
    initialize_database,
    list_scan_records,
    record_scan,
)


class SQLiteStorageTests(unittest.TestCase):
    def test_records_and_lists_scan_metadata(self):
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / "routehawk.sqlite"
            metadata = {
                "run_id": "20260507-120000",
                "generated_at": "2026-05-07T12:00:00Z",
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
                "changed_endpoints": 0,
            }

            record_scan(path, metadata, {"endpoints": []}, {"new_count": 2})
            records = list_scan_records(path)

            self.assertEqual(len(records), 1)
            self.assertEqual(records[0].run_id, "20260507-120000")
            self.assertEqual(records[0].target, "http://localhost:8088")
            self.assertEqual(records[0].scope, ["localhost"])
            self.assertEqual(records[0].endpoint_count, 9)
            self.assertEqual(records[0].new_endpoint_count, 2)
            self.assertEqual(records[0].removed_endpoint_count, 1)
            self.assertEqual(fetch_scan_payload(path, "20260507-120000", "result_json"), {"endpoints": []})
            self.assertEqual(fetch_scan_payload(path, "20260507-120000", "diff_json"), {"new_count": 2})

    def test_fetch_scan_payload_returns_none_for_missing_run(self):
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / "routehawk.sqlite"

            self.assertIsNone(fetch_scan_payload(path, "missing", "result_json"))

    def test_initialize_database_creates_parent_directory(self):
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / "nested" / "routehawk.sqlite"

            initialize_database(path)

            self.assertTrue(path.exists())


if __name__ == "__main__":
    unittest.main()
