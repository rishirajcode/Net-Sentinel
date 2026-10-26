import os
import re
import socket
import subprocess
from pathlib import Path
from pydantic import BaseModel
from typing import Optional

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / "netsentinel.db"
OUI_CACHE_PATH = DATA_DIR / "oui_cache.json"

class SystemNetworkInfo(BaseModel):
    ip_address: str = "127.0.0.1"
    subnet: str = "192.168.1.0/24"
    gateway: str = "192.168.1.1"
    mac_address: str = "00:00:00:00:00:00"
    interface_name: str = "Unknown"

_cached_network_info: Optional[SystemNetworkInfo] = None

def detect_windows_network(force_refresh: bool = False) -> SystemNetworkInfo:
    """
    Detect active IPv4, subnet, default gateway, and host MAC on Windows
    using ipconfig and socket routing without elevated privileges.
    Results are cached in memory for high-performance responsiveness.
    """
    global _cached_network_info
    if _cached_network_info and not force_refresh:
        return _cached_network_info

    info = SystemNetworkInfo()
    
    # Method 1: Use UDP routing check to find the active outbound IP
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        detected_ip = s.getsockname()[0]
        s.close()
        if detected_ip and not detected_ip.startswith("127."):
            info.ip_address = detected_ip
    except Exception:
        pass

    # Method 2: Parse ipconfig /all to correlate Gateway, Subnet Mask, Interface, and MAC
    try:
        proc = subprocess.run(
            ["ipconfig", "/all"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False
        )
        output = proc.stdout
        
        sections = re.split(r"(?:\r?\n){2,}(?=[A-Za-z0-9])", output)
        for section in sections:
            if "Media disconnected" in section:
                continue
            
            ip_match = re.search(r"IPv4 Address[ .]+:\s*([\d\.]+)", section)
            gw_match = re.search(r"Default Gateway[ .]+:\s*([\d\.]+)", section)
            mask_match = re.search(r"Subnet Mask[ .]+:\s*([\d\.]+)", section)
            mac_match = re.search(r"Physical Address[ .]+:\s*([0-9A-Fa-f\-]{17})", section)
            
            if ip_match:
                curr_ip = ip_match.group(1).replace("(Preferred)", "").strip()
                if info.ip_address == "127.0.0.1" or curr_ip == info.ip_address:
                    info.ip_address = curr_ip
                    if gw_match:
                        info.gateway = gw_match.group(1).strip()
                    if mac_match:
                        info.mac_address = mac_match.group(1).replace("-", ":").lower()
                    
                    mask = mask_match.group(1).strip() if mask_match else "255.255.255.0"
                    try:
                        cidr = sum(bin(int(x)).count('1') for x in mask.split('.'))
                        ip_parts = [int(p) for p in curr_ip.split('.')]
                        mask_parts = [int(p) for p in mask.split('.')]
                        net_parts = [ip_parts[i] & mask_parts[i] for i in range(4)]
                        net_addr = ".".join(str(p) for p in net_parts)
                        info.subnet = f"{net_addr}/{cidr}"
                    except Exception:
                        info.subnet = "192.168.1.0/24"
                    break
    except Exception:
        pass

    _cached_network_info = info
    return info

class Settings:
    APP_NAME: str = "Net Sentinel"
    APP_VERSION: str = "1.0.0"
    APP_TAGLINE: str = "See Every Device. Control Your Network."
    DEVELOPER: str = "Software Vantage"
    
    # Server Binding
    HOST: str = os.getenv("NETSENTINEL_HOST", "127.0.0.1")
    PORT: int = int(os.getenv("NETSENTINEL_PORT", "8000"))
    
    # Security & Auth
    SECRET_KEY: str = os.getenv("NETSENTINEL_SECRET", "netsentinel-software-vantage-secret-key-2026")
    SESSION_COOKIE_NAME: str = "netsentinel_session"
    REQUIRE_AUTH: bool = True
    
    # Router Defaults
    ROUTER_GATEWAY: str = os.getenv("NETSENTINEL_ROUTER_IP", "192.168.1.1")
    ROUTER_MODEL: str = "DBC HGU-V210-4AC"
    
    # Discovery Defaults
    SCAN_TIMEOUT_SEC: int = int(os.getenv("NETSENTINEL_SCAN_TIMEOUT", "10"))
    MAX_THREADS: int = int(os.getenv("NETSENTINEL_THREADS", "50"))
    SCAN_INTERVAL_MINUTES: int = int(os.getenv("NETSENTINEL_SCAN_INTERVAL", "15"))

settings = Settings()
