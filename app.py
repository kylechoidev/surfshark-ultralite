#!/usr/bin/env python3
"""
SurfShark Ultra-Lite Web UI Control Center — v1.1.1
Features:
- Kernel route ground truth detection (checks 'ip route get' for dev surfshark_wg)
- Robust multi-probe egress verification with fallback (ipinfo.io -> ipify -> ip.sb -> icanhazip)
- Smart caching to avoid rate-limiting and unnecessary network traffic
- Eco-Mode Freezer (suspends Electron renderers to drop CPU to 0.0% while keeping WireGuard active)
- Safe: never touches or suspends the Electron main process
"""
import json
import os
import re
import signal
import subprocess
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BASE = os.path.dirname(os.path.abspath(__file__))
HOME = os.path.expanduser("~")
PORT = int(os.environ.get("SURFSHARK_WEBUI_PORT", "8777"))
CACHE_PATH = os.path.join(HOME, ".config/Surfshark/cache.json")

_cached_state = {
    "connected_real": False,
    "tunnel_routed": False,
    "tunnel_stalled": False,
    "public_ip": None,
    "exit_org": "",
    "exit_geo": "",
    "probe_source": "",
    "fallback_active": False,
    "probe_warnings": [],
    "gui_running": False,
    "gui_frozen": False,
    "locations_count": 0,
    "last_check": 0,
    "version": "1.2.2"
}
_state_lock = threading.Lock()
_last_full_probe = 0
_last_routed_state = None

def locations():
    if os.path.exists(CACHE_PATH):
        try:
            cache = json.load(open(CACHE_PATH))
            clusters = cache.get("/v5/server/clusters/all")
            if isinstance(clusters, dict):
                return clusters.get("value", [])
            return clusters or []
        except Exception:
            pass
    return []

def is_wg_routed():
    """Kernel-level ground truth: does default routing egress through surfshark_wg?"""
    try:
        res = subprocess.run(["ip", "route", "get", "8.8.8.8"], capture_output=True, text=True, timeout=2)
        return "dev surfshark_wg" in res.stdout
    except Exception:
        return False

def get_surfshark_session_metadata():
    """Reads official Surfshark app's last active session metadata from globals.json."""
    try:
        p = os.path.join(HOME, ".config/Surfshark/globals.json")
        if os.path.exists(p):
            data = json.load(open(p))
            for ev in reversed(data.get("vpn_events", [])):
                if ev.get("name") in ("VpnConnectIntent", "VpnConnected"):
                    payload = ev.get("payload", {})
                    loc = payload.get("vpn_exit_location_name")
                    cc = payload.get("vpn_exit_country_code")
                    if loc and cc:
                        return {
                            "city": loc,
                            "country_code": cc.upper(),
                            "display": f"{loc}, {cc}"
                        }
    except Exception:
        pass
    return None

def get_surfshark_session_location():
    """Reads official Surfshark app's last active session metadata from globals.json."""
    meta = get_surfshark_session_metadata()
    return meta["display"] if meta else None

_COMMON_COUNTRY_ALIASES = {
    "US": ["united states", "usa", "u.s.", "u.s.a.", "united states of america"],
    "GB": ["united kingdom", "uk", "great britain", "england", "scotland", "wales"],
    "UK": ["united kingdom", "uk", "great britain"],
    "CA": ["canada"],
    "AU": ["australia"],
    "DE": ["germany", "deutschland"],
    "FR": ["france"],
    "JP": ["japan"],
    "SG": ["singapore"],
    "NL": ["netherlands", "holland"],
    "TH": ["thailand"],
    "VN": ["vietnam"],
    "KR": ["south korea", "korea"],
    "BR": ["brazil", "brasil"],
    "ES": ["spain", "espana"],
    "IT": ["italy", "italia"],
    "CH": ["switzerland", "swiss"],
    "SE": ["sweden"],
    "NO": ["norway"],
    "DK": ["denmark"],
    "FI": ["finland"],
    "IE": ["ireland"],
    "NZ": ["new zealand"],
    "IN": ["india"],
    "MX": ["mexico"],
    "ZA": ["south africa"],
    "HK": ["hong kong"],
    "TW": ["taiwan"],
}

def get_country_aliases(country_code):
    """Returns lowercased set of country names and aliases for a given 2-letter ISO country code."""
    cc = (country_code or "").strip().upper()
    if not cc:
        return set()
    aliases = {cc.lower()}
    for cluster in locations():
        if cluster.get("countryCode", "").upper() == cc:
            cname = cluster.get("country")
            if cname:
                aliases.add(cname.lower())
    for alias in _COMMON_COUNTRY_ALIASES.get(cc, []):
        aliases.add(alias.lower())
    return aliases

def is_location_match(session_meta, probed_meta, probed_geo):
    """
    Checks if probed egress geo matches the active Surfshark session.
    Prevents false-positive discrepancies between ISO country codes ('US')
    and full country names ('United States').
    """
    if not session_meta:
        return True

    session_cc = session_meta.get("country_code", "").upper()
    session_city = session_meta.get("city", "").strip().lower()

    probed_cc = (probed_meta.get("country_code") or "").strip().upper()
    probed_country = (probed_meta.get("country") or "").strip().lower()
    probed_city = (probed_meta.get("city") or "").strip().lower()
    probed_geo_lower = (probed_geo or "").lower()

    # 1. Country code exact match (e.g. US == US)
    if session_cc and probed_cc and session_cc == probed_cc:
        return True

    # 2. Known country names / aliases match probed country or are contained in probed_geo
    known_aliases = get_country_aliases(session_cc)
    if probed_country and probed_country in known_aliases:
        return True
    if any(alias in probed_geo_lower for alias in known_aliases):
        return True

    # 3. City exact or substring match (e.g. "Charlotte" == "Charlotte")
    if session_city and (session_city == probed_city or session_city in probed_geo_lower):
        return True

    # 4. Token boundary match for 2-letter country code in probed_geo
    tokens = [t.lower() for t in re.findall(r'[a-zA-Z]+', probed_geo_lower)]
    if session_cc.lower() in tokens:
        return True

    return False

def probe_egress():
    """
    Probe public IP and geo/org metadata.
    Tries ip-api.com first (better datacenter/VPN mapping), then ipinfo.io,
    falling back to resilient IP probe endpoints.
    Explicitly records all provider errors so fallbacks are NEVER silent.
    """
    warnings = []

    # 1. Primary probe: ip-api.com (accurate VPN datacenter city/country mapping)
    try:
        req = urllib.request.Request("http://ip-api.com/json", headers={"User-Agent": "curl/8"})
        with urllib.request.urlopen(req, timeout=4) as r:
            data = json.loads(r.read().decode())
            if data.get("status") == "success":
                ip = data.get("query")
                city = data.get("city", "")
                country = data.get("country", "")
                country_code = data.get("countryCode", "")
                geo = f"{city}, {country}".strip(", ")
                org = data.get("org") or data.get("isp") or data.get("as", "")
                meta = {"city": city, "country": country, "country_code": country_code}
                if ip:
                    return ip, geo, org, "ip-api.com", False, warnings, meta
            else:
                warnings.append(f"Primary probe (ip-api.com) returned status error: {data.get('message', 'unknown')}")
    except Exception as e:
        warnings.append(f"Primary probe (ip-api.com) failed: {e}")

    # 2. Secondary probe: ipinfo.io (fallback)
    try:
        req = urllib.request.Request("https://ipinfo.io/json", headers={"User-Agent": "curl/8"})
        with urllib.request.urlopen(req, timeout=4) as r:
            data = json.loads(r.read().decode())
            ip = data.get("ip")
            org = data.get("org", "")
            city = data.get("city", "")
            country = data.get("country", "")
            geo = f"{city}, {country}".strip(", ")
            meta = {"city": city, "country": country, "country_code": country}
            if ip:
                warnings.append("Using fallback GeoIP provider: ipinfo.io")
                return ip, geo, org, "ipinfo.io (fallback)", True, warnings, meta
    except Exception as e:
        warnings.append(f"Secondary probe (ipinfo.io) failed: {e}")

    # 3. Resilient IP fallback endpoints if GeoIP APIs time out or rate-limit
    fallbacks = [
        ("api.ipify.org", "https://api.ipify.org"),
        ("api.ip.sb", "https://api.ip.sb/ip"),
        ("icanhazip.com", "https://icanhazip.com")
    ]
    for name, url in fallbacks:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "curl/8"})
            with urllib.request.urlopen(req, timeout=4) as r:
                ip = r.read().decode().strip()[:64]
                if ip and re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
                    warnings.append(f"All GeoIP APIs failed; IP resolved via emergency fallback {name}")
                    return ip, "", "", f"{name} (fallback IP only)", True, warnings, {}
        except Exception as e:
            warnings.append(f"Fallback {name} failed: {e}")

    warnings.append("All egress probes failed (tunnel blackholed or connection offline)")
    return None, "", "", "None (all probes failed)", True, warnings, {}


def get_electron_processes():
    """Finds Surfshark Electron processes; distinguishes zygote renderers from the main process."""
    res = subprocess.run(["ps", "-eo", "pid,state,%cpu,cmd"], capture_output=True, text=True)
    renderers = []
    main_pids = []
    for line in res.stdout.splitlines():
        if "/opt/Surfshark/surfshark" in line:
            parts = line.strip().split(None, 3)
            if len(parts) >= 2:
                pid = int(parts[0])
                state = parts[1]
                if "--type=zygote" in line:
                    renderers.append((pid, state))
                else:
                    main_pids.append((pid, state))
    return main_pids, renderers

def probe_network(force_egress=False):
    global _last_full_probe, _last_routed_state
    
    # 1. Immediate local kernel route check (~2ms)
    wg_routed = is_wg_routed()
    now = time.time()
    
    # Check if route state changed (e.g. user toggled VPN)
    route_changed = (_last_routed_state is not None and _last_routed_state != wg_routed)
    _last_routed_state = wg_routed
    
    # Determine if we should perform an external egress probe:
    # - If forced (manual refresh or after freeze/unfreeze)
    # - If route state just flipped
    # - If we don't have an IP yet
    # - Or every 20 seconds periodically
    needs_egress = (
        force_egress or 
        route_changed or 
        _cached_state["public_ip"] is None or 
        (now - _last_full_probe > 20)
    )
    
    ip = _cached_state["public_ip"]
    geo = _cached_state["exit_geo"]
    org = _cached_state["exit_org"]
    probe_source = _cached_state["probe_source"]
    fallback_active = _cached_state["fallback_active"]
    warnings = list(_cached_state["probe_warnings"])
    
    if needs_egress:
        probed_ip, probed_geo, probed_org, probe_src, fb_active, probe_warns, probed_meta = probe_egress()
        _last_full_probe = now
        warnings = probe_warns
        fallback_active = fb_active
        probe_source = probe_src or ""
        
        if probed_ip:
            ip = probed_ip
            session_meta = get_surfshark_session_metadata() if wg_routed else None
            ss_loc = session_meta["display"] if session_meta else None
            
            if probed_geo:
                geo = probed_geo
                # Detect and warn if GeoIP returned a conflicting country against session
                if session_meta and not is_location_match(session_meta, probed_meta, probed_geo):
                    fallback_active = True
                    mismatch_warn = f"Location discrepancy: probe returned '{probed_geo}' ({probe_src}) but Surfshark session is '{ss_loc}'"
                    if mismatch_warn not in warnings:
                        warnings.append(mismatch_warn)
                    geo = f"{probed_geo} [Session: {ss_loc}]"
            elif ss_loc:
                geo = ss_loc
            elif ip != _cached_state.get("public_ip"):
                geo = ""

            if probed_org:
                org = probed_org
            elif ip != _cached_state.get("public_ip"):
                org = ""
        else:
            ip = None
            probe_source = "None (probes failed)"
            fallback_active = True

    # Ground truth connection logic:
    # If routed via WireGuard AND external egress succeeded -> 100% Protected
    connected_real = bool(wg_routed and ip)
    tunnel_stalled = bool(wg_routed and not ip)

    main_pids, renderers = get_electron_processes()
    gui_running = len(main_pids) > 0 or len(renderers) > 0
    gui_frozen = any("T" in st for _, st in renderers)
    locs = locations()

    with _state_lock:
        _cached_state["connected_real"] = connected_real
        _cached_state["tunnel_routed"] = wg_routed
        _cached_state["tunnel_stalled"] = tunnel_stalled
        _cached_state["public_ip"] = ip
        _cached_state["exit_org"] = org
        _cached_state["exit_geo"] = geo
        _cached_state["probe_source"] = probe_source
        _cached_state["fallback_active"] = fallback_active
        _cached_state["probe_warnings"] = warnings
        _cached_state["gui_running"] = gui_running
        _cached_state["gui_frozen"] = gui_frozen
        _cached_state["locations_count"] = len(locs)
        _cached_state["last_check"] = now

def background_worker():
    while True:
        try:
            probe_network()
        except Exception:
            pass
        time.sleep(2)

threading.Thread(target=background_worker, daemon=True).start()

def freeze_gui():
    _, renderers = get_electron_processes()
    count = 0
    for pid, _ in renderers:
        try:
            os.kill(pid, signal.SIGSTOP)
            count += 1
        except Exception:
            pass
    probe_network(force_egress=False)
    return count > 0, f"Suspended {count} UI renderer processes (CPU dropped to 0.0%)"

def unfreeze_gui():
    _, renderers = get_electron_processes()
    count = 0
    for pid, _ in renderers:
        try:
            os.kill(pid, signal.SIGCONT)
            count += 1
        except Exception:
            pass
    probe_network(force_egress=False)
    return count > 0, f"Resumed {count} UI renderer processes"

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="application/json"):
        data = body.encode() if isinstance(body, str) else json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype + "; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/" or self.path.startswith("/?"):
            page = open(os.path.join(BASE, "index.html")).read()
            self._send(200, page, "text/html")
        elif self.path in ("/favicon.ico", "/icon.png"):
            icon_path = os.path.join(BASE, "icon.png")
            if os.path.exists(icon_path):
                with open(icon_path, "rb") as f:
                    data = f.read()
                self.send_response(200)
                self.send_header("Content-Type", "image/png")
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Cache-Control", "public, max-age=86400")
                self.end_headers()
                self.wfile.write(data)
            else:
                self._send(404, {"error": "icon not found"})
        elif self.path == "/api/state":
            with _state_lock:
                self._send(200, dict(_cached_state))
        elif self.path == "/api/locations":
            out = [{"connectionName": l["connectionName"], "country": l["country"],
                    "countryCode": l.get("countryCode"), "city": l.get("location"),
                    "tags": l.get("tags") or []} for l in locations()]
            self._send(200, out)
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        content_len = int(self.headers.get("Content-Length", 0)) or 0
        body = json.loads(self.rfile.read(content_len) or b"{}")
        
        if self.path == "/api/freeze":
            ok, msg = freeze_gui()
            self._send(200, {"ok": ok, "message": msg})
        elif self.path == "/api/unfreeze":
            ok, msg = unfreeze_gui()
            self._send(200, {"ok": ok, "message": msg})
        elif self.path == "/api/open-gui":
            unfreeze_gui()
            subprocess.Popen(["gtk-launch", "surfshark"])
            self._send(200, {"ok": True, "message": "Opening Surfshark app window…"})
        elif self.path == "/api/refresh":
            probe_network(force_egress=True)
            with _state_lock:
                self._send(200, dict(_cached_state))
        else:
            self._send(404, {"error": "not found"})

def main():
    print(f"[surfshark-control-center] Running on http://127.0.0.1:{PORT}")
    ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()

if __name__ == "__main__":
    main()
