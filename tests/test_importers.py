import unittest

from routehawk.importers.httpx_json import import_httpx_json
from routehawk.importers.nmap_xml import import_nmap_xml
from routehawk.importers.nuclei_json import import_nuclei_json
from routehawk.importers.subfinder_json import import_subfinder_json


class ImporterTests(unittest.TestCase):
    def test_imports_httpx_json_lines(self):
        assets = import_httpx_json(
            '{"url":"https://app.example.com","status_code":200,"title":"App","tech":["nginx"]}\n'
        )

        self.assertEqual(len(assets), 1)
        self.assertEqual(assets[0].host, "app.example.com")
        self.assertEqual(assets[0].scheme, "https")
        self.assertEqual(assets[0].status, 200)
        self.assertEqual(assets[0].technologies, ["nginx"])

    def test_imports_subfinder_json_and_plain_lines(self):
        hosts = import_subfinder_json('{"host":"api.example.com"}\nwww.example.com\n')

        self.assertEqual(hosts, ["api.example.com", "www.example.com"])

    def test_imports_nuclei_json_lines_as_manual_findings(self):
        findings = import_nuclei_json(
            '{"template-id":"exposure","matched-at":"https://app.example.com/debug","info":{"name":"Debug","severity":"high"}}\n'
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].type, "imported_nuclei")
        self.assertEqual(findings[0].severity, "high")
        self.assertIn("Nuclei template: exposure", findings[0].evidence)

    def test_imports_nmap_xml_open_ports(self):
        assets = import_nmap_xml(
            """
            <nmaprun>
              <host>
                <address addr="127.0.0.1" addrtype="ipv4"/>
                <hostnames><hostname name="localhost"/></hostnames>
                <ports>
                  <port protocol="tcp" portid="80"><state state="open"/></port>
                  <port protocol="tcp" portid="443"><state state="open"/></port>
                </ports>
              </host>
            </nmaprun>
            """
        )

        self.assertEqual(len(assets), 1)
        self.assertEqual(assets[0].host, "localhost")
        self.assertEqual(assets[0].scheme, "https")
        self.assertEqual(assets[0].technologies, ["tcp/80", "tcp/443"])


if __name__ == "__main__":
    unittest.main()
