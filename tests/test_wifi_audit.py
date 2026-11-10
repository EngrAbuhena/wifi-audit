"""Offline tests: no radio access, network scans, or external dependencies."""

import importlib.util
import io
import json
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import TestCase, mock

script = Path(__file__).resolve().parents[1] / "wifi_audit.py"
spec = importlib.util.spec_from_file_location("wifi_audit", script)
audit = importlib.util.module_from_spec(spec)
import sys
sys.modules[spec.name] = audit  # dataclasses resolves annotations via module lookup
spec.loader.exec_module(audit)


class AuditTests(TestCase):
    def test_identifier_masking(self):
        self.assertEqual(audit.mask_identifier("AA:BB:CC:DD:EE:FF"), "AA:BB:CC:xx:xx:xx")
        self.assertIsNone(audit.mask_identifier(None))
        network = audit.Network(ssid="Example", bssid="AA:BB:CC:DD:EE:FF")
        self.assertEqual(audit.serialize_network(network, False)["bssid"], "AA:BB:CC:xx:xx:xx")
        self.assertEqual(audit.serialize_network(network, True)["bssid"], network.bssid)

    def test_security_findings(self):
        cases = [("Open", "HIGH"), ("WEP", "CRITICAL"), ("WPA", "HIGH"),
                 ("WPA2", "MEDIUM"), ("WPA3", "INFO")]
        for security, severity in cases:
            with self.subTest(security=security):
                findings = audit.assess([audit.Network(ssid="Test", security=security, active=True)], False)
                self.assertEqual(findings[0].severity, severity)

    def test_default_assesses_active_connection_only(self):
        networks = [audit.Network(ssid="Active", security="WPA3", active=True),
                    audit.Network(ssid="Other", security="WEP")]
        self.assertEqual(len(audit.assess(networks, False)), 1)
        self.assertEqual(len(audit.assess(networks, True)), 2)

    def test_weak_signal_and_empty_connection(self):
        network = audit.Network(ssid="Weak", security="WPA3", signal=25, active=True)
        self.assertIn("Weak signal", audit.assess([network], False)[1].title)
        self.assertEqual(audit.assess([], False)[0].severity, "INFO")

    def test_linux_nmcli_parsing(self):
        raw = r"yes:Cafe\:West:AA\:BB\:CC\:DD\:EE\:FF:6:2437 MHz:72:WPA2" + "\n"
        with mock.patch.object(audit.shutil, "which", return_value="/usr/bin/nmcli"), \
             mock.patch.object(audit, "run", return_value=raw) as execute:
            networks = audit.linux_networks(False)
        self.assertEqual(len(networks), 1)
        self.assertEqual(networks[0].ssid, "Cafe:West")
        self.assertEqual(networks[0].bssid, "AA:BB:CC:DD:EE:FF")
        self.assertTrue(networks[0].active)
        self.assertEqual(networks[0].signal, 72)
        self.assertNotIn("--rescan", execute.call_args.args[0])

    def test_refuses_to_run_without_acknowledgement(self):
        with mock.patch("sys.argv", ["wifi_audit.py"]), \
             mock.patch.object(audit, "get_networks") as get_networks, \
             redirect_stderr(io.StringIO()) as err:
            self.assertEqual(audit.main(), 2)
        get_networks.assert_not_called()
        self.assertIn("authorization acknowledgement", err.getvalue())

    def test_json_report_with_mocked_os_data(self):
        network = audit.Network(ssid="Example", bssid="AA:BB:CC:DD:EE:FF", security="WPA3", active=True)
        with mock.patch("sys.argv", ["wifi_audit.py", "--authorized", "I_HAVE_PERMISSION", "--json"]), \
             mock.patch.object(audit, "get_networks", return_value=([network], "")), \
             redirect_stdout(io.StringIO()) as out:
            self.assertEqual(audit.main(), 0)
        payload = json.loads(out.getvalue())
        self.assertEqual(payload["networks"][0]["bssid"], "AA:BB:CC:xx:xx:xx")
        self.assertEqual(payload["findings"][0]["severity"], "INFO")
