"""Network device discovery/control: subnet math, vendor fallback, and the
ARP-disconnect bookkeeping -- with all real packet sends mocked out, since
these must pass without admin rights or a live network."""
import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import detectors.network_devices as nd
from detectors.network_devices import (
    ARPDisconnector, Device, DeviceControlRegistry, NetworkDeviceScanner,
)


class DeviceRoleTests(unittest.TestCase):

    def test_self_role(self):
        self.assertEqual(Device(ip="1.1.1.1", mac="aa", is_self=True).role, "This PC")

    def test_gateway_role(self):
        self.assertEqual(Device(ip="1.1.1.1", mac="aa", is_gateway=True).role, "Router / Gateway")

    def test_plain_device_has_no_role(self):
        self.assertEqual(Device(ip="1.1.1.1", mac="aa").role, "")


class SubnetMathTests(unittest.TestCase):

    def test_cidr_from_slash24(self):
        net = NetworkDeviceScanner._cidr_from_netmask("192.168.1.42", "255.255.255.0")
        self.assertEqual(net, "192.168.1.0/24")

    def test_cidr_from_slash16(self):
        net = NetworkDeviceScanner._cidr_from_netmask("10.101.0.5", "255.255.0.0")
        self.assertEqual(net, "10.101.0.0/16")


class LargeSubnetCapTests(unittest.TestCase):
    """A real network reported a /18 (262,144 addresses) as this host's
    netmask, which made the sweep try to ARP-request every one of them and
    hang indefinitely. scan() must narrow an oversized subnet down."""

    def test_oversized_subnet_is_narrowed_before_sweeping(self):
        scanner = NetworkDeviceScanner()
        captured_targets = []

        def fake_srp(pkt, timeout, verbose, iface):
            captured_targets.append(pkt[nd.ARP].pdst)
            return [], []

        with patch.object(nd, "srp", side_effect=fake_srp), \
             patch.object(scanner, "local_network_info", return_value={
                 "iface": "eth0", "ip": "10.101.177.57", "mac": "64:bc:58:1a:91:81",
                 "netmask": "255.255.192.0",   # /18
                 "gateway_ip": "",
             }):
            scanner.scan(on_progress=lambda _m: None)

        self.assertEqual(captured_targets, ["10.101.177.0/24"])

    def test_normal_slash24_is_left_alone(self):
        scanner = NetworkDeviceScanner()
        captured_targets = []

        def fake_srp(pkt, timeout, verbose, iface):
            captured_targets.append(pkt[nd.ARP].pdst)
            return [], []

        with patch.object(nd, "srp", side_effect=fake_srp), \
             patch.object(scanner, "local_network_info", return_value={
                 "iface": "eth0", "ip": "192.168.1.42", "mac": "aa:bb:cc:dd:ee:ff",
                 "netmask": "255.255.255.0",   # /24
                 "gateway_ip": "",
             }):
            scanner.scan(on_progress=lambda _m: None)

        self.assertEqual(captured_targets, ["192.168.1.0/24"])


class VendorLookupFallbackTests(unittest.TestCase):

    def test_falls_back_to_oui_table_when_request_fails(self):
        scanner = NetworkDeviceScanner()
        with patch.object(nd, "requests") as mock_requests:
            mock_requests.get.side_effect = Exception("no network")
            vendor = scanner.resolve_vendor("B8:27:EB:11:22:33")
        self.assertEqual(vendor, "Raspberry Pi Foundation")

    def test_unknown_prefix_returns_empty_not_crash(self):
        scanner = NetworkDeviceScanner()
        with patch.object(nd, "requests") as mock_requests:
            mock_requests.get.side_effect = Exception("no network")
            vendor = scanner.resolve_vendor("DE:AD:BE:EF:00:01")
        self.assertEqual(vendor, "")

    def test_result_is_cached(self):
        scanner = NetworkDeviceScanner()
        with patch.object(nd, "requests") as mock_requests:
            mock_requests.get.side_effect = Exception("no network")
            scanner.resolve_vendor("B8:27:EB:11:22:33")
            scanner.resolve_vendor("B8:27:EB:11:22:33")
        self.assertEqual(mock_requests.get.call_count, 1)


class ARPDisconnectorTests(unittest.TestCase):
    """Patches module-level `send` so no packet is ever actually transmitted."""

    def test_poison_once_sends_forged_gateway_reply(self):
        with patch.object(nd, "send") as mock_send, \
             patch.object(nd, "get_if_hwaddr", return_value="11:11:11:11:11:11"):
            d = ARPDisconnector("192.168.1.50", "aa:aa:aa:aa:aa:aa",
                                 "192.168.1.1", "bb:bb:bb:bb:bb:bb")
            d._poison_once()
        self.assertEqual(mock_send.call_count, 1)
        pkt = mock_send.call_args[0][0]
        self.assertEqual(pkt.op, 2)                       # ARP reply
        self.assertEqual(pkt.pdst, "192.168.1.50")        # sent to the target
        self.assertEqual(pkt.psrc, "192.168.1.1")         # claiming to be the gateway
        self.assertEqual(pkt.hwsrc, "11:11:11:11:11:11")  # but with OUR mac

    def test_restore_sends_real_gateway_mac(self):
        with patch.object(nd, "send") as mock_send, \
             patch.object(nd, "get_if_hwaddr", return_value="11:11:11:11:11:11"), \
             patch.object(nd, "_RESTORE_PACKETS", 1), \
             patch("time.sleep"):
            d = ARPDisconnector("192.168.1.50", "aa:aa:aa:aa:aa:aa",
                                 "192.168.1.1", "bb:bb:bb:bb:bb:bb")
            d._restore()
        pkt = mock_send.call_args[0][0]
        self.assertEqual(pkt.hwsrc, "bb:bb:bb:bb:bb:bb")  # the real gateway MAC, not ours

    def test_start_then_stop_restores_and_clears_running(self):
        events = []
        with patch.object(nd, "send"), \
             patch.object(nd, "get_if_hwaddr", return_value="11:11:11:11:11:11"), \
             patch.object(nd, "_POISON_INTERVAL", 0.01), \
             patch.object(nd, "_RESTORE_PACKETS", 1):
            d = ARPDisconnector("192.168.1.50", "aa:aa:aa:aa:aa:aa",
                                 "192.168.1.1", "bb:bb:bb:bb:bb:bb",
                                 on_event=events.append)
            ok, _ = d.start()
            self.assertTrue(ok)
            self.assertTrue(d.is_running())
            ok, _ = d.stop()
            self.assertTrue(ok)
            self.assertFalse(d.is_running())
        self.assertEqual(events[0]["rule_name"], "Device Disconnected (ARP)")
        self.assertEqual(events[1]["rule_name"], "Device Reconnected")

    def test_double_start_is_rejected(self):
        with patch.object(nd, "send"), \
             patch.object(nd, "get_if_hwaddr", return_value="11:11:11:11:11:11"), \
             patch.object(nd, "_POISON_INTERVAL", 0.01):
            d = ARPDisconnector("192.168.1.50", "aa:aa:aa:aa:aa:aa",
                                 "192.168.1.1", "bb:bb:bb:bb:bb:bb")
            d.start()
            ok, msg = d.start()
            d.stop()
        self.assertFalse(ok)
        self.assertIn("already", msg.lower())


class DeviceControlRegistryTests(unittest.TestCase):

    def test_disconnect_then_reconnect_updates_state(self):
        with patch.object(nd, "send"), \
             patch.object(nd, "get_if_hwaddr", return_value="11:11:11:11:11:11"), \
             patch.object(nd, "_POISON_INTERVAL", 0.01):
            reg = DeviceControlRegistry()
            ok, _ = reg.disconnect("192.168.1.50", "aa:aa:aa:aa:aa:aa",
                                    "192.168.1.1", "bb:bb:bb:bb:bb:bb")
            self.assertTrue(ok)
            self.assertTrue(reg.is_disconnected("192.168.1.50"))

            ok, _ = reg.reconnect("192.168.1.50")
            self.assertTrue(ok)
            self.assertFalse(reg.is_disconnected("192.168.1.50"))

    def test_reconnecting_unknown_ip_fails_cleanly(self):
        reg = DeviceControlRegistry()
        ok, msg = reg.reconnect("10.0.0.99")
        self.assertFalse(ok)
        self.assertIn("not currently", msg.lower())

    def test_reconnect_all_clears_everything(self):
        with patch.object(nd, "send"), \
             patch.object(nd, "get_if_hwaddr", return_value="11:11:11:11:11:11"), \
             patch.object(nd, "_POISON_INTERVAL", 0.01):
            reg = DeviceControlRegistry()
            reg.disconnect("192.168.1.50", "aa:aa", "192.168.1.1", "bb:bb")
            reg.disconnect("192.168.1.51", "cc:cc", "192.168.1.1", "bb:bb")
            reg.reconnect_all()
        self.assertFalse(reg.is_disconnected("192.168.1.50"))
        self.assertFalse(reg.is_disconnected("192.168.1.51"))


if __name__ == "__main__":
    unittest.main()
