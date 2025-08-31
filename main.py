import requests, time, os, re, json, csv, base64, subprocess, threading
from datetime import datetime, timezone
import pyshark
from colorama import init, Fore as F, Style as S

init(autoreset=True)

PORT_FILE = "ports.txt"
OUT_DIR = "results"
LOOT_FILE = os.path.join(OUT_DIR, "loot.json")
HEADERS = {"User-Agent": "Mozilla/5.0 (ReconBot)"}
TIMEOUT = 6
SLEEP_BETWEEN = 0.3
SNIFF_TRAFFIC = True
SNIFF_INTERFACE = "tun0"
SNIFF_DURATION = 8

SAFE_ENDPOINTS = [
    "/", "/json/logger/update", "/status", "/version", "/json/status"
]

TITLE_RE = re.compile(r"<title>(.*?)</title>", re.IGNORECASE | re.DOTALL)

def ensure_dirs():
    os.makedirs(OUT_DIR, exist_ok=True)

def fetch_ports():
    with open(PORT_FILE, "r") as f:
        return [int(p.strip()) for p in f if p.strip().isdigit()]

def get_text_title(html):
    m = TITLE_RE.search(html or "")
    return re.sub(r"\s+", " ", m.group(1).strip()) if m else None

def mmh3_hash32(data):
    import mmh3
    return mmh3.hash(data)

def safe_get(url):
    try:
        return requests.get(url, headers=HEADERS, timeout=TIMEOUT, allow_redirects=True)
    except requests.RequestException:
        return None

def sniff_port(ip, port, duration, outdir):
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    fname = os.path.join(outdir, f"sniff_{ip}_{port}_{ts}.pcapng")
    print(f"{F.YELLOW}[~] Sniffing {ip}:{port} for {duration}s...")
    cmd = ["tshark", "-i", SNIFF_INTERFACE, "-a", f"duration:{duration}", "-f",
           f"tcp and host {ip} and port {port}", "-w", fname]
    try:
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print(f"{F.GREEN}[+] PCAP saved → {fname}")

        # Auto-convert to text and JSON
        subprocess.run(["tshark", "-r", fname, "-V"], stdout=open(fname + ".txt", "w"))
        subprocess.run(["tshark", "-r", fname, "-T", "json"], stdout=open(fname + ".json", "w"))
        print(f"{F.GREEN}[+] Converted to {fname}.txt and {fname}.json")
    except Exception as e:
        print(f"{F.RED}[!] Sniff error: {e}")

def analyze_pcap(pcap_file):
    cap = pyshark.FileCapture(pcap_file, display_filter="http")
    for pkt in cap:
        if hasattr(pkt, 'http'):
            print(f"{F.MAGENTA}[HTTP] {pkt.http.request_method} → {pkt.http.get('host', '')}{pkt.http.get('request_uri', '')}")

def probe_port(ip, port):
    port_outdir = os.path.join(OUT_DIR, ip, str(port))
    os.makedirs(port_outdir, exist_ok=True)

    if SNIFF_TRAFFIC:
        sniff_thread = threading.Thread(target=sniff_port, args=(ip, port, SNIFF_DURATION, port_outdir))
        sniff_thread.start()

    base = f"http://{ip}:{port}"
    r = safe_get(base + "/")
    if not r:
        return None

    cookie = r.headers.get("Set-Cookie", "")
    title = get_text_title(r.text)
    favicon_hash = None

    fav = safe_get(base + "/favicon.ico")
    if fav and fav.ok and fav.content:
        favicon_hash = mmh3_hash32(fav.content)

    endpoints_info = []
    for ep in SAFE_ENDPOINTS:
        rep = safe_get(base + ep)
        snippet = (rep.text[:200].replace("\n", " ") if rep and rep.text else None)
        endpoints_info.append({
            "path": ep,
            "status": rep.status_code if rep else None,
            "snippet": snippet
        })

    return {
        "ip": ip,
        "port": port,
        "status": r.status_code,
        "title": title,
        "cookie": cookie.split(";", 1)[0] if cookie else "",
        "favicon_mmh3": favicon_hash,
        "endpoints": endpoints_info
    }

def save_loot(results):
    ensure_dirs()

    summary = []

    for entry in results:
        ip_dir = os.path.join(OUT_DIR, entry["ip"])
        port_dir = os.path.join(ip_dir, str(entry["port"]))
        os.makedirs(port_dir, exist_ok=True)

        with open(os.path.join(port_dir, "loot.json"), "w") as f:
            json.dump(entry, f, indent=2)

        summary.append(entry)

    with open(LOOT_FILE, "w") as f:
        json.dump(summary, f, indent=2)

    print(f"{F.GREEN}[+] Per-port loot saved under → {OUT_DIR}/<ip>/<port>/loot.json")
    print(f"{F.GREEN}[+] Summary loot saved → {LOOT_FILE}")

def recon_loop():
    print(f"{S.BRIGHT}{F.CYAN}>>> Maritime UniProxy Recon Scanner <<<\n")
    target = input(f"{F.YELLOW}[?] Target IP: ").strip()
    if not target:
        print(f"{F.RED}[!] No IP entered. Exiting.")
        return
    print(f"{F.CYAN}[+] Scanning {target}...\n")

    ports = fetch_ports()
    loot = []
    for p in ports:
        print(f"{F.BLUE}[*] Port {p}: ", end="", flush=True)
        result = probe_port(target, p)
        if result:
            loot.append(result)
            print(f"{F.GREEN}OK")
        else:
            print(f"{F.RED}No match")
        time.sleep(SLEEP_BETWEEN)

    if loot:
        save_loot(loot)
    else:
        print(f"{F.RED}[-] No UniProxy signatures detected.")

if __name__ == "__main__":
    recon_loop()
