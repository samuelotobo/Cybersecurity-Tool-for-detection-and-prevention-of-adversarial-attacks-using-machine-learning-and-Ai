"""
Network Topology & Geolocation Map.

Geolocates attacker IPs via ip-api.com (free, no key required, 45 req/min)
and builds an interactive Leaflet.js map using the `folium` library.

The map is saved as an HTML file and can be opened in:
  - A PyQt6 QWebEngineView widget (desktop app)
  - Any web browser
  - The Flask web dashboard (served as a static route)
"""

import json
import threading
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Callable

import requests

try:
    import folium
    from folium.plugins import MarkerCluster
    _FOLIUM_OK = True
except ImportError:
    _FOLIUM_OK = False


_MAP_FILE    = Path(__file__).parent.parent / "network_map.html"
_CACHE_FILE  = Path(__file__).parent.parent / "geo_cache.json"
_GEO_API     = "http://ip-api.com/batch"
_RATE_DELAY  = 1.0    # seconds between API batch calls (api limit: 45 req/min)
_MAX_MARKERS = 300    # cap rendered markers to keep map fast
_MAX_EVENTS  = 1000   # cap stored events to limit memory

# Severity → CircleMarker colour
_SEV_COLOR = {
    "critical": "#ef4444",
    "high":     "#f97316",
    "medium":   "#eab308",
    "low":      "#3b82f6",
}

_SKIP_PREFIXES = (
    "10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
    "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
    "127.", "::1", "169.254.", "0.",
)


class GeoMapper:
    """
    Collects attacker IPs, resolves their geolocation, and renders
    an interactive map showing attack origins with severity markers.
    """

    def __init__(
        self,
        on_alert: Callable[[dict], None] | None = None,
        auto_rebuild_after: int = 15,
    ):
        self._on_alert          = on_alert or (lambda _: None)
        self._auto_rebuild      = auto_rebuild_after
        self._lock              = threading.Lock()
        self._pending_count     = 0
        self._rebuild_lock      = threading.Lock()   # prevent concurrent rebuilds
        self._last_rebuild_ts   = 0.0
        self._folium_alerted    = False              # only emit the install warning once
        self._cache: dict[str, dict]    = {}
        self._events: list[dict]        = []
        self._ip_counts: dict[str, int] = defaultdict(int)
        self._load_cache()

    # ── Public ──────────────────────────────────────────────────────────────

    def track_ip(self, ip: str, rule_name: str = "", severity: str = "high") -> None:
        """Record a new threat event and trigger a background map rebuild if due."""
        if _is_private(ip):
            return
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with self._lock:
            self._ip_counts[ip] += 1
            self._events.append({
                "ip":        ip,
                "rule":      rule_name,
                "severity":  severity,
                "timestamp": ts,
            })
            # Trim old events to cap memory
            if len(self._events) > _MAX_EVENTS:
                self._events = self._events[-_MAX_EVENTS:]
            self._pending_count += 1
            pending = self._pending_count

        if pending >= self._auto_rebuild:
            now = time.monotonic()
            # Don't rebuild more often than every 45 s to stay within rate limit
            if now - self._last_rebuild_ts >= 45:
                with self._lock:
                    self._pending_count = 0
                self._last_rebuild_ts = now
                threading.Thread(
                    target=self._resolve_and_build, daemon=True, name="GeoMapper"
                ).start()

    def build_map(self) -> Path:
        """Synchronously resolve all pending IPs and rebuild the map. Returns map path."""
        self._resolve_and_build()
        return _MAP_FILE

    def map_path(self) -> Path:
        return _MAP_FILE

    def map_exists(self) -> bool:
        return _MAP_FILE.exists()

    def get_stats(self) -> dict:
        with self._lock:
            return {
                "unique_countries": len({
                    g.get("country") for g in self._cache.values()
                    if g.get("status") == "success"
                }),
                "unique_ips":   len(self._ip_counts),
                "total_events": len(self._events),
            }

    # ── Internal ────────────────────────────────────────────────────────────

    def _resolve_and_build(self) -> None:
        # Only one rebuild at a time
        if not self._rebuild_lock.acquire(blocking=False):
            return
        try:
            with self._lock:
                all_ips = list(self._ip_counts.keys())
            unresolved = [ip for ip in all_ips if ip not in self._cache]

            for i in range(0, len(unresolved), 15):
                batch = unresolved[i:i + 15]
                try:
                    resp = requests.post(
                        _GEO_API,
                        json=[{"query": ip} for ip in batch],
                        timeout=8,
                    )
                    if resp.status_code == 200:
                        with self._lock:
                            for ip, geo in zip(batch, resp.json()):
                                self._cache[ip] = geo
                        self._save_cache()
                except Exception:
                    pass
                if i + 15 < len(unresolved):
                    time.sleep(_RATE_DELAY)

            self._render_map()
        finally:
            self._rebuild_lock.release()

    def _render_map(self) -> None:
        if not _FOLIUM_OK:
            if not self._folium_alerted:
                self._folium_alerted = True
                self._on_alert({
                    "rule_name": "GeoMap Unavailable",
                    "severity":  "low",
                    "source_ip": "localhost",
                    "message":   "Install folium to enable the geo map: pip install folium",
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "category":  "system",
                })
            return

        with self._lock:
            events = list(self._events)
            cache  = dict(self._cache)
            counts = dict(self._ip_counts)

        # Build per-IP summary: keep highest-severity event per IP
        _sev_rank = {"critical": 3, "high": 2, "medium": 1, "low": 0}
        ip_summary: dict[str, dict] = {}
        for ev in events:
            ip = ev["ip"]
            if ip not in ip_summary or _sev_rank.get(ev["severity"], 0) > _sev_rank.get(ip_summary[ip]["severity"], 0):
                ip_summary[ip] = ev

        m = folium.Map(
            location=[20, 0],
            zoom_start=2,
            tiles="CartoDB dark_matter",
            prefer_canvas=True,
            max_bounds=True,
            no_wrap=True,
        )

        # Use MarkerCluster only when there are many points
        plotted = 0
        container = MarkerCluster(name="Attacker IPs").add_to(m) if len(ip_summary) > 20 else m

        for ip, ev in list(ip_summary.items())[:_MAX_MARKERS]:
            geo = cache.get(ip, {})
            if geo.get("status") != "success":
                continue
            lat = geo.get("lat", 0)
            lon = geo.get("lon", 0)
            if lat == 0 and lon == 0:
                continue

            color  = _SEV_COLOR.get(ev["severity"], "#3b82f6")
            count  = counts.get(ip, 1)
            radius = min(6 + count, 18)

            popup_html = (
                f"<div style='font-family:sans-serif;font-size:12px;min-width:180px'>"
                f"<b style='color:{color}'>{ip}</b><br>"
                f"<b>Rule:</b> {ev['rule']}<br>"
                f"<b>Severity:</b> {ev['severity'].upper()}<br>"
                f"<b>Country:</b> {geo.get('country','?')}<br>"
                f"<b>City:</b> {geo.get('city','?')}<br>"
                f"<b>ISP:</b> {geo.get('isp','?')}<br>"
                f"<b>Events:</b> {count}<br>"
                f"<b>Last seen:</b> {ev['timestamp']}"
                f"</div>"
            )

            folium.CircleMarker(
                location=[lat, lon],
                radius=radius,
                color=color,
                fill=True,
                fill_color=color,
                fill_opacity=0.75,
                weight=1.5,
                popup=folium.Popup(popup_html, max_width=260),
                tooltip=f"{ip} — {ev['severity'].upper()} ({count} events)",
            ).add_to(container)
            plotted += 1

        legend_html = f"""
        <div style="position:fixed;bottom:30px;right:30px;z-index:1000;
                    background:#111827;padding:12px 16px;border-radius:10px;
                    border:1px solid #374151;color:#e5e7eb;font-size:12px;
                    font-family:sans-serif;box-shadow:0 4px 12px rgba(0,0,0,.5)">
            <div style="font-weight:700;margin-bottom:8px;font-size:13px">
                Threat Map &nbsp;<span style="color:#6b7280">{plotted} IPs</span>
            </div>
            <div><span style="color:#ef4444;font-size:16px">●</span>&nbsp; Critical</div>
            <div><span style="color:#f97316;font-size:16px">●</span>&nbsp; High</div>
            <div><span style="color:#eab308;font-size:16px">●</span>&nbsp; Medium</div>
            <div><span style="color:#3b82f6;font-size:16px">●</span>&nbsp; Low</div>
            <div style="color:#6b7280;font-size:10px;margin-top:6px">
                Circle size = event count
            </div>
        </div>
        """
        m.get_root().html.add_child(folium.Element(legend_html))

        if len(ip_summary) > 20:
            folium.LayerControl().add_to(m)

        try:
            m.save(str(_MAP_FILE))
        except Exception:
            pass

    def _load_cache(self) -> None:
        try:
            if _CACHE_FILE.exists():
                self._cache = json.loads(_CACHE_FILE.read_text(encoding="utf-8"))
        except Exception:
            self._cache = {}

    def _save_cache(self) -> None:
        try:
            _CACHE_FILE.write_text(
                json.dumps(self._cache, separators=(",", ":")),
                encoding="utf-8",
            )
        except Exception:
            pass


def _is_private(ip: str) -> bool:
    return any(ip.startswith(p) for p in _SKIP_PREFIXES)
