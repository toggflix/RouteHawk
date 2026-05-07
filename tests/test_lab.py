import os
import unittest
from unittest.mock import patch

from labs.demo_server import _server_address


class DemoLabTests(unittest.TestCase):
    def test_demo_server_defaults_to_localhost(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(_server_address(), ("127.0.0.1", 8088))

    def test_demo_server_can_bind_for_docker(self):
        with patch.dict(
            os.environ,
            {
                "ROUTEHAWK_LAB_HOST": "0.0.0.0",
                "ROUTEHAWK_LAB_PORT": "9090",
            },
            clear=True,
        ):
            self.assertEqual(_server_address(), ("0.0.0.0", 9090))

    def test_demo_server_falls_back_on_invalid_port(self):
        with patch.dict(os.environ, {"ROUTEHAWK_LAB_PORT": "nope"}, clear=True):
            self.assertEqual(_server_address(), ("127.0.0.1", 8088))


if __name__ == "__main__":
    unittest.main()
