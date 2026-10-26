# Net Sentinel

**Developer & Brand:** Software Vantage  
**Tagline:** *See Every Device. Control Your Network.*

[![Platform](https://img.shields.io/badge/Platform-Windows%2011-blue.svg)](https://microsoft.com)
[![Python](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-brightgreen.svg)](https://python.org)
[![FastAPI](https://img.shields.io/badge/Backend-FastAPI-teal.svg)](https://fastapi.tiangolo.com)
[![Self-Hosted](https://img.shields.io/badge/Hosting-Self--Hosted%20(Local)-orange.svg)]()
[![Zero-Cloud](https://img.shields.io/badge/Privacy-100%25%20Zero--Cloud-success.svg)]()

---

## 1. Project Overview

**Net Sentinel** is a free, self-hosted, lightweight home network monitoring and device management application developed and branded by **Software Vantage**.

Designed as a modern, private alternative to cloud-dependent tools like Fing, Net Sentinel runs completely on your local Windows laptop without requiring:
- Any subscription, cloud server, or external account.
- Docker, Linux, or a Raspberry Pi.
- Proprietary software or packet interception.

It enables you to discover every device connected to your home Wi-Fi, monitor device statuses in real time, identify unknown endpoints and randomized MAC addresses, and manage access control through your home router.

---

## 2. Target Environment & Architecture

- **Host Machine:** Windows 11 Laptop (Python 3.13).
- **Target Router:** DBC HGU-V210-4AC GPON/EPON ONT Router (`http://192.168.1.1`).
- **Dashboard Access:** Laptop browser (`http://127.0.0.1:8000`) and Android mobile browser over home Wi-Fi.
- **Persistent Storage:** SQLite (`data/netsentinel.db`).
- **Discovery Engine:** Dual-mode architecture:
  1. **Windows Native Win32 Engine:** High-performance concurrent ARP discovery using Windows `iphlpapi.dll`'s `SendARP` API via `ctypes` + multi-threaded ICMP sweep. Scans an entire `/24` subnet (254 IPs) in ~10 seconds with zero external binaries required.
  2. **Nmap Engine:** Automatically leveraged when `nmap` is present in system PATH (`nmap -sn -PR -PE`) with safe XML parsing. If Nmap is missing, Net Sentinel informs you gracefully and operates seamlessly with the native engine.
- **MAC Vendor & Randomization Engine:** Built-in offline IEEE OUI lookup database, with intelligent detection for IEEE 802 Locally Administered Addresses (LAA) used by Android 10+ and iOS 14+ private MAC randomization.
- **Router Adapter Architecture:** Modular adapter structure separating discovery and dashboard from router operations:
  - `DbcHguAdapter`: Specifically inspects DBC HGU-V210-4AC capabilities.
  - `ManualRouterAdapter`: Guided step-by-step procedure for DBC router MAC Filtering (Blacklist mode) when direct automation is unverified.
  - `MockRouterAdapter`: For isolated testing and development.
  - **Zero-Simulation Policy:** Net Sentinel never fakes successful blocking; access control rules must be verified.
  - **Safety Guards:** Hardcoded safeguards strictly prevent blocking the default gateway (`192.168.1.1`), the monitoring laptop itself, or the current user device.

---

## 3. Dashboard Features

### Summary Overview (8 Verified Cards)
1. **Total Discovered:** All endpoints seen on your network.
2. **Currently Online:** Active and reachable endpoints.
3. **Offline Devices:** Retained with last-seen timestamps (never automatically purged).
4. **Trusted Devices:** Devices you have explicitly verified.
5. **Unknown Devices:** Newly detected devices requiring review.
6. **Blocked by Router:** Devices under router access-control restrictions.
7. **Most Recent Scan:** Timestamp and discovery engine used.
8. **Router Status:** Live reachability and model detection for the DBC HGU-V210-4AC.

### Device Inventory Table
- Device name, custom label, and hostname.
- IPv4 address and formatted hardware MAC address.
- Manufacturer / Vendor identification.
- Device categorization (Router, Host Laptop, Mobile, Smart Home/IoT, PC, Printer).
- Real-time status indicators (Online green dot / Offline gray dot).
- Quick filters: `All`, `Online`, `Offline`, `Unknown`, `Trusted`, `Blocked`.
- Real-time search across IP, MAC, friendly name, and vendor.
- Single-click CSV export compliant with RFC 4180.

### Device Details & History Modal
- Historical scan observations and response latency.
- Past IP movements and address change tracking.
- In-place renaming, category classification, and custom notes editor.

---

## 4. Beginner-Friendly Installation Guide (Windows)

### Prerequisites
- Windows 10 or Windows 11.
- Python 3.10+ (Python 3.13 tested and confirmed).
  *(Make sure **"Add Python to PATH"** was checked when installing Python).*

### Step 1: Open Project Folder
Extract or clone the project files to a folder on your laptop, e.g.:
`D:\Net sentinal`

### Step 2: Run Installer
Double-click **`install.bat`** (or open PowerShell in the directory and run `.\install.bat`).
The script will:
- Check your Python installation.
- Create an isolated virtual environment (`.\venv`).
- Install all required libraries (`fastapi`, `uvicorn`, `pydantic`, `jinja2`, `requests`, `pytest`).
- Check for Nmap (and inform you of the fallback native engine if not installed).
- Initialize the local SQLite database.

---

## 5. Running Net Sentinel

### To Start:
Double-click **`start.bat`**.
- It starts the local Uvicorn web server at `http://127.0.0.1:8000`.
- It automatically launches your default web browser to the Net Sentinel dashboard.

### To Stop:
- Press `Ctrl+C` in the command window, or double-click **`stop.bat`**.

---

## 6. Accessing the Dashboard from Your Android Phone

Net Sentinel can be accessed from any Android smartphone connected to your home Wi-Fi:

1. Open **Settings** inside the Net Sentinel dashboard.
2. Check the box **"Enable LAN Dashboard Access (Bind to 0.0.0.0)"** and click **Save Settings**.
3. Note your laptop's local IP address displayed in the settings (e.g., `http://192.168.1.38:8000`).
4. On your Android phone, connect to your home Wi-Fi, open Chrome or your preferred browser, and navigate to:
   `http://192.168.1.38:8000`
5. Log in with your Net Sentinel administrator credentials.

### Windows Firewall Configuration (If Phone Cannot Connect)
If your phone cannot reach `http://192.168.1.38:8000`, Windows Defender Firewall may be blocking inbound traffic on port 8000. To permit it:
1. Open PowerShell as Administrator.
2. Run this command:
   ```powershell
   New-NetFirewallRule -DisplayName "Net Sentinel Local Dashboard" -Direction Inbound -LocalPort 8000 -Protocol TCP -Action Allow -Profile Private
   ```
3. This safely allows inbound connections on port 8000 only on your private home network.

---

## 7. Router Access Control (DBC HGU-V210-4AC)

The DBC HGU-V210-4AC GPON ONT router manages access control via its web interface:

1. In the dashboard, click **Block** next to an unauthorized device.
2. Review the confirmation modal showing:
   - Target device name, IP address, and MAC address.
   - Router gateway address (`192.168.1.1`).
3. Check the confirmation box.
4. If automated firmware API is unverified for your specific ISP firmware build, Net Sentinel provides the exact guided steps:
   - Open `http://192.168.1.1` in your browser.
   - Log in with your router credentials.
   - Go to `Security` -> `MAC Filter`.
   - Set mode to **Blacklist** (Denylist).
   - Paste the target MAC and save.
5. Net Sentinel records the action with a timestamp in the audit trail.

---

## 8. Running Automated Tests

Net Sentinel includes an automated test suite verifying models, security rules, router adapters, discovery, and API endpoints.

To run tests:
```powershell
.\venv\Scripts\pytest -v
```

Expected output:
```
============================= test session starts =============================
17 passed in 1.42s
```

---

## 9. Security & Privacy Highlights

- **Zero Plaintext Credentials:** Admin passwords hashed with 100,000 rounds of PBKDF2-HMAC-SHA256 with unique cryptographic salts.
- **CSRF Defense:** State-changing API operations (scan, trust, block, settings) enforce `X-CSRF-Token` validation.
- **Safe Subprocess Execution:** Subprocesses pass command argument arrays directly to Windows APIs—no `shell=True` with interpolated strings.
- **Private Subnet Enforcement:** All scanning targets are strictly validated against RFC 1918 private subnets (e.g. `192.168.0.0/16`, `10.0.0.0/8`). Public internet scans are categorically refused.
- **Audit Logging:** Every administrative and security-relevant action is recorded in the SQLite audit log without storing sensitive passwords or tokens.

---

## 10. Project Structure

```
d:\Net sentinal\
├── app/
│   ├── main.py                  # FastAPI application & dashboard routes
│   ├── config.py                # System network detection & settings
│   ├── database.py              # SQLite schema, transactions & backups
│   ├── models.py                # Pydantic schemas & input validation
│   ├── api/
│   │   ├── auth.py              # Administrator login, setup & CSRF
│   │   ├── devices.py           # Device inventory & CSV export endpoints
│   │   ├── scan.py              # Discovery scan execution & history
│   │   ├── router.py            # DBC router control & status
│   │   └── settings.py          # Configuration & audit trail
│   ├── services/
│   │   ├── discovery.py         # Dual-engine host discovery (SendARP + Nmap)
│   │   ├── vendor.py            # IEEE OUI resolution & LAA randomization detection
│   │   ├── device_inventory.py  # Inventory filters, metrics & CSV generator
│   │   ├── router_adapter.py    # DBC HGU-V210-4AC & Mock adapter architecture
│   │   ├── audit_log.py         # Persistent security audit logging
│   │   └── monitoring.py        # Periodic background scan scheduler
│   ├── templates/
│   │   └── index.html           # Responsive dashboard single-page UI
│   └── static/
│       ├── css/styles.css       # Professional network-security styling
│       └── js/app.js            # Frontend reactive controller & modals
├── data/
│   ├── netsentinel.db           # SQLite database
│   └── oui_cache.json           # Local IEEE OUI manufacturer database
├── tests/
│   ├── test_models.py           # Subnet validation & schemas
│   ├── test_discovery.py        # MAC normalization & vendor classification
│   ├── test_router.py           # Safety guards & adapter operations
│   ├── test_security.py         # Password hashing & verification
│   └── test_api.py              # API handlers integration suite
├── install.bat                  # One-click Windows setup script
├── start.bat                    # One-click start script
├── stop.bat                     # Clean shutdown script
├── requirements.txt             # Python dependencies
├── pytest.ini                   # Test configuration
├── .env.example                 # Example environment variables
├── .gitignore                   # Version control ignore list
└── README.md                    # Comprehensive documentation
```

---

## 11. Troubleshooting

| Problem | Cause | Solution |
|---|---|---|
| `'python' is not recognized` | Python not in Windows PATH | Re-run Python installer and check **"Add Python to PATH"**. |
| `Nmap not detected in PATH` | Nmap not installed | Net Sentinel automatically uses native Windows ARP & ICMP. Optional: Install Nmap from [nmap.org](https://nmap.org/download.html). |
| Mobile phone cannot open dashboard | Windows Firewall blocking port 8000 | In Settings, enable LAN access and run the firewall command listed in Section 6. |
| Router status shows `Reachable (Web)` | Admin credentials required | Log into `http://192.168.1.1` to review MAC Filtering table directly. |

---

*Net Sentinel is proudly developed and maintained by **Software Vantage**.*  
*Tagline: **See Every Device. Control Your Network.***
