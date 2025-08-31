# Maritime UniProxy Recon Scanner

⚓️ A high-signal recon tool to detect and fingerprint exposed **Maritime UniProxy** ports, capture live traffic, and extract useful metadata (titles, cookies, endpoints, and optional pcap dumps).

---

## 🔍 Features

- Parallel port-based scanning of Maritime UniProxy instances
- Automatic title, cookie, and favicon hash extraction
- Probes known safe endpoints (e.g., `/json/logger/update`, `/status`)
- Optional traffic sniffing via `tshark`
- PCAP auto-conversion to `.txt` and `.json` with `pyshark` support
- Color-coded output and loot saving to `results/`

---

## 🚀 Usage

1. **Install requirements**:
    ```bash
    pip install -r requirements.txt
    sudo apt install tshark -y
    ```

2. **Edit `ports.txt`** with port numbers to scan (one per line).

3. **Run the tool**:
    ```bash
    python3 recon.py
    ```

4. **Results saved to**:
    - `results/<IP>/port_<port>.json`
    - PCAPs: `sniff_<ip>_<port>_TIMESTAMP.pcapng` + `.txt`/`.json` (optional)

---

## 📁 Output Format

Each result includes:
```json
{
  "ip": "192.168.1.100",
  "port": 8086,
  "status": 200,
  "title": "Maritime UniProxy",
  "cookie": "uniproxy8085=...",
  "favicon_mmh3": 123456789,
  "endpoints": [
    {
      "path": "/",
      "status": 200,
      "snippet": "<!DOCTYPE html>..."
    }
  ]
}
