"""
CipherNet Automated Headless Test Suite (PySide6)
Validates service primitives, PySide6 desktop UI mounting, tab navigation,
interactive widgets, background workers, and cryptographic operations.
Runs headlessly via QT_QPA_PLATFORM=offscreen.
"""

from __future__ import annotations
import os
import sys
from pathlib import Path
import unittest

# Ensure offscreen Qt platform for headless CI / CLI testing
os.environ["QT_QPA_PLATFORM"] = "offscreen"

# Setup paths
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import QApplication

from ciphernet.app import CipherNetApp, HelpDialog
from ciphernet.services.crypto_service import CryptoService
from ciphernet.services.detection_service import DetectionService
from ciphernet.services.event_service import EventService
from ciphernet.services.network_service import NetworkService
from ciphernet.services.settings_service import SettingsService


# Ensure singleton QApplication for unittest runner
qt_app = QApplication.instance()
if not qt_app:
    qt_app = QApplication(["ciphernet_test", "-platform", "offscreen"])


class TestServices(unittest.TestCase):
    """Unit tests for non-UI services."""

    def test_settings_service(self):
        s = SettingsService()
        self.assertIsNotNone(s.get("theme"))
        s.set("theme", "charcoal-rose", auto_save=False)
        self.assertEqual(s.get("theme"), "charcoal-rose")
        s.set("test_key", 42, auto_save=False)
        self.assertEqual(s.get("test_key"), 42)

    def test_event_service(self):
        es = EventService(max_capacity=50)
        e = es.log("Test Event", "Details", severity="HIGH", category="SIMULATION", simulated=True)
        self.assertEqual(e.severity, "HIGH")
        self.assertTrue(e.simulated)

        events = es.get_events(limit=10, severity="HIGH")
        self.assertTrue(len(events) >= 1)
        self.assertEqual(events[0].severity, "HIGH")

        metrics = es.get_metrics()
        self.assertGreater(metrics["total_events"], 0)
        self.assertIn("CRITICAL", metrics["by_severity"])

    def test_network_service(self):
        ns = NetworkService(show_loopback=True)
        stats = ns.get_summary_stats()
        self.assertIn("local_ip", stats)
        self.assertIn("hostname", stats)

        ifaces = ns.get_interfaces()
        self.assertIsInstance(ifaces, list)

        conns = ns.get_connections()
        self.assertIsInstance(conns, list)

    def test_detection_service(self):
        es = EventService()
        ds = DetectionService(event_service=es)
        rules = ds.get_rules()
        self.assertGreaterEqual(len(rules), 5)

        # Trigger single attack
        alert = ds.trigger_single_attack()
        self.assertIsNotNone(alert)
        self.assertTrue(alert.simulated)
        self.assertIn("[SIMULATED]", alert.title)

    def test_crypto_service(self):
        cs = CryptoService()

        # AES-GCM
        enc = cs.encrypt_aes_gcm("Test Plaintext", "TestPassphrase123!", is_passphrase=True)
        self.assertIn("ciphertext_hex", enc)
        self.assertIn("tag_hex", enc)
        self.assertIn("nonce_hex", enc)

        ok, dec = cs.decrypt_aes_gcm(
            enc["ciphertext_hex"],
            enc["tag_hex"],
            enc["nonce_hex"],
            "TestPassphrase123!",
            is_passphrase=True,
            salt_hex=enc["salt_hex"],
        )
        self.assertTrue(ok)
        self.assertEqual(dec, "Test Plaintext")

        # Tampered decryption failure
        bad_ct = enc["ciphertext_hex"][:-2] + ("00" if enc["ciphertext_hex"][-2:] != "00" else "ff")
        ok_tamper, _ = cs.decrypt_aes_gcm(
            bad_ct,
            enc["tag_hex"],
            enc["nonce_hex"],
            "TestPassphrase123!",
            is_passphrase=True,
            salt_hex=enc["salt_hex"],
        )
        self.assertFalse(ok_tamper)

        # RSA
        kp = cs.generate_rsa_keypair(2048)
        self.assertEqual(kp["key_size"], 2048)
        self.assertIn("BEGIN PUBLIC KEY", kp["public_pem"])

        ok_sig, sig = cs.sign_message("Message to sign", kp["private_pem"])
        self.assertTrue(ok_sig)

        ok_ver, _ = cs.verify_signature("Message to sign", sig, kp["public_pem"])
        self.assertTrue(ok_ver)

        ok_bad, _ = cs.verify_signature("Altered message", sig, kp["public_pem"])
        self.assertFalse(ok_bad)

        # Hashing
        h = cs.hash_text("test")
        self.assertIn("SHA-256", h)
        self.assertEqual(len(h["SHA-256"]), 64)


class TestPySide6DesktopApp(unittest.TestCase):
    """UI test case validating the PySide6 standalone desktop application."""

    def setUp(self):
        self.app_window = CipherNetApp()
        self.app_window.show()
        qt_app.processEvents()

    def tearDown(self):
        self.app_window.close()
        qt_app.processEvents()

    def test_window_initialization(self):
        self.assertEqual(self.app_window.current_tab, "tab-overview")
        self.assertIsNotNone(self.app_window.centralWidget())
        self.assertEqual(self.app_window.stack.count(), 7)

    def test_tab_switching(self):
        tabs = [
            "tab-network",
            "tab-ids",
            "tab-crypto",
            "tab-logs",
            "tab-settings",
            "tab-creators",
            "tab-overview",
        ]
        for tid in tabs:
            self.app_window.switch_tab(tid)
            qt_app.processEvents()
            self.assertEqual(self.app_window.current_tab, tid)
            self.assertEqual(self.app_window.stack.currentWidget(), self.app_window.views[tid])

    def test_overview_module_interactions(self):
        overview = self.app_window.view_overview
        self.assertIsNotNone(overview.card_host)
        self.assertIsNotNone(overview.traffic_chart)
        self.assertIsNotNone(overview.iface_table)
        self.assertIsNotNone(overview.events_table)

        # Trigger simulated attack burst via quick action
        initial_events = len(self.app_window.event_service.get_events(category="SIMULATION"))
        overview.btn_attack.click()
        qt_app.processEvents()
        new_events = len(self.app_window.event_service.get_events(category="SIMULATION"))
        self.assertGreater(new_events, initial_events)

        # Toggle IDS engine via quick action
        running_before = self.app_window.detection_service.is_running
        overview.btn_ids_toggle.click()
        qt_app.processEvents()
        self.assertEqual(self.app_window.detection_service.is_running, not running_before)
        overview.btn_ids_toggle.click()
        qt_app.processEvents()
        self.assertEqual(self.app_window.detection_service.is_running, running_before)

    def test_network_monitor_module(self):
        self.app_window.switch_tab("tab-network")
        qt_app.processEvents()
        net_view = self.app_window.view_network

        self.assertIsNotNone(net_view.conns_table)
        net_view.refresh_connections()
        qt_app.processEvents()

        # Test filter selection
        net_view.combo_proto.setCurrentIndex(1)  # TCP
        qt_app.processEvents()
        self.assertEqual(net_view.selected_proto, "TCP")

    def test_intrusion_detection_module(self):
        self.app_window.switch_tab("tab-ids")
        qt_app.processEvents()
        ids_view = self.app_window.view_ids

        self.assertIsNotNone(ids_view.radar)
        self.assertIsNotNone(ids_view.rules_table)
        self.assertIsNotNone(ids_view.timeline_table)

        # Fire attack burst
        ids_view.btn_fire.click()
        qt_app.processEvents()
        self.assertGreater(ids_view.timeline_table.rowCount(), 0)

        # Test rule toggle
        rules = self.app_window.detection_service.get_rules()
        first_rule = rules[0]
        init_state = first_rule.enabled
        ids_view._on_rule_double_clicked(0, 0)
        qt_app.processEvents()
        self.assertEqual(first_rule.enabled, not init_state)
        # Restore state
        ids_view._on_rule_double_clicked(0, 0)
        qt_app.processEvents()
        self.assertEqual(first_rule.enabled, init_state)

    def test_cryptography_lab_module(self):
        self.app_window.switch_tab("tab-crypto")
        qt_app.processEvents()
        crypto_view = self.app_window.view_crypto

        # AES encrypt and decrypt
        crypto_view.input_aes_plain.setText("Unit test secret message")
        crypto_view.action_aes_encrypt()
        qt_app.processEvents()
        self.assertIsNotNone(crypto_view.cached_aes_result)

        crypto_view.action_aes_decrypt(tamper=False)
        qt_app.processEvents()
        self.assertIn("AUTHENTICATION & DECRYPTION SUCCESSFUL", crypto_view.output_aes_dec.text())

        # AES tamper test
        crypto_view.action_aes_decrypt(tamper=True)
        qt_app.processEvents()
        self.assertIn("AUTHENTICATION FAILURE", crypto_view.output_aes_dec.text())

        # RSA signing & verification
        crypto_view.action_rsa_sign()
        qt_app.processEvents()
        self.assertTrue(len(crypto_view.cached_signature) > 0)

        crypto_view.action_rsa_verify(tamper=False)
        qt_app.processEvents()
        self.assertIn("DIGITAL SIGNATURE VALID", crypto_view.output_rsa_sig.text())

        crypto_view.action_rsa_verify(tamper=True)
        qt_app.processEvents()
        self.assertIn("VERIFICATION FAILED", crypto_view.output_rsa_sig.text())

        # Multi-algorithm hashing
        crypto_view.input_hash_text.setText("Sample Hash String")
        crypto_view.action_compute_hashes()
        qt_app.processEvents()
        self.assertIn("SHA-256", crypto_view.output_multi_hash.text())

        # File checksum verification
        crypto_view.input_file_path.setText(str(PROJECT_ROOT / "ciphernet" / "config" / "settings.json"))
        crypto_view.input_expected_hash.setText("")
        crypto_view.action_verify_file()
        qt_app.processEvents()

    def test_security_logs_module(self):
        self.app_window.switch_tab("tab-logs")
        qt_app.processEvents()
        logs_view = self.app_window.view_logs

        self.assertIsNotNone(logs_view.logs_table)
        self.assertGreater(logs_view.logs_table.rowCount(), 0)

        # Test export logs
        export_target = PROJECT_ROOT / "logs" / "test_audit_export.json"
        self.app_window.event_service.export_to_json(export_target)
        self.assertTrue(export_target.exists())
        export_target.unlink()  # Clean up

    def test_settings_module(self):
        self.app_window.switch_tab("tab-settings")
        qt_app.processEvents()
        settings_view = self.app_window.view_settings

        self.assertIsNotNone(settings_view.combo_theme)
        self.assertIsNotNone(settings_view.btn_save)
        self.assertIsNotNone(settings_view.btn_reset)

        # Test immediate theme application
        idx_neon = settings_view.combo_theme.findData("cyber-neon")
        settings_view.combo_theme.setCurrentIndex(idx_neon)
        qt_app.processEvents()
        self.assertEqual(self.app_window.settings_service.get("theme"), "cyber-neon")

        idx_gruv = settings_view.combo_theme.findData("gruvbox-dark")
        settings_view.combo_theme.setCurrentIndex(idx_gruv)
        qt_app.processEvents()
        self.assertEqual(self.app_window.settings_service.get("theme"), "gruvbox-dark")

        idx_rose = settings_view.combo_theme.findData("charcoal-rose")
        settings_view.combo_theme.setCurrentIndex(idx_rose)
        qt_app.processEvents()
        self.assertEqual(self.app_window.settings_service.get("theme"), "charcoal-rose")

    def test_creators_module(self):
        self.app_window.switch_tab("tab-creators")
        qt_app.processEvents()
        creators_view = self.app_window.view_creators
        self.assertIsNotNone(creators_view)

    def test_hotkeys_and_telemetry(self):
        # Test toggle IDS action
        init_ids = self.app_window.detection_service.is_running
        self.app_window.action_toggle_ids()
        qt_app.processEvents()
        self.assertEqual(self.app_window.detection_service.is_running, not init_ids)
        self.app_window.action_toggle_ids()
        qt_app.processEvents()
        self.assertEqual(self.app_window.detection_service.is_running, init_ids)

        # Test telemetry tick
        self.app_window.on_telemetry_tick()
        qt_app.processEvents()

        # Test Help dialog creation
        help_dlg = HelpDialog(self.app_window)
        self.assertIsNotNone(help_dlg)


if __name__ == "__main__":
    unittest.main()
