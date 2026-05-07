import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from routehawk.cli import main


class CliImportTests(unittest.TestCase):
    def test_import_file_writes_httpx_assets(self):
        with TemporaryDirectory() as temporary:
            input_path = Path(temporary) / "httpx.jsonl"
            output_path = Path(temporary) / "imported.json"
            input_path.write_text(
                '{"url":"https://app.example.com","status_code":200,"title":"App"}\n',
                encoding="utf-8",
            )

            exit_code = main(
                [
                    "import-file",
                    "--type",
                    "httpx",
                    "--input",
                    str(input_path),
                    "--out",
                    str(output_path),
                ]
            )

            payload = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(exit_code, 0)
            self.assertEqual(payload["assets"][0]["host"], "app.example.com")


if __name__ == "__main__":
    unittest.main()
