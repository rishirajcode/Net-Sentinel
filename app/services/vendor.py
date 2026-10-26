import json
import re
from pathlib import Path
from typing import Optional, Tuple
from app.config import OUI_CACHE_PATH

class VendorService:
    def __init__(self, cache_file: Path = OUI_CACHE_PATH):
        self.cache_file = cache_file
        self.oui_db: dict[str, str] = {}
        self.load_oui_cache()

    def load_oui_cache(self) -> None:
        if self.cache_file.exists():
            try:
                with open(self.cache_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    # Normalize keys to upper XX:XX:XX
                    self.oui_db = {k.upper().replace("-", ":"): v for k, v in data.items()}
            except Exception:
                self.oui_db = {}

    @staticmethod
    def normalize_mac(mac: Optional[str]) -> Optional[str]:
        if not mac:
            return None
        cleaned = re.sub(r"[^0-9A-Fa-f]", "", mac).lower()
        if len(cleaned) == 12:
            return ":".join(cleaned[i:i+2] for i in range(0, 12, 2))
        return mac.lower().replace("-", ":")

    @staticmethod
    def is_randomized_mac(mac: Optional[str]) -> bool:
        """
        Detects if a MAC address has the IEEE 802 Locally Administered Address (LAA) bit set.
        Modern Android and iOS devices randomize MAC addresses using LAA bit (x2, x6, xA, xE).
        """
        if not mac:
            return False
        normalized = VendorService.normalize_mac(mac)
        if not normalized or len(normalized) < 2:
            return False
        try:
            first_byte = int(normalized[:2], 16)
            return (first_byte & 0x02) != 0
        except ValueError:
            return False

    def lookup_vendor(self, mac: Optional[str]) -> Optional[str]:
        if not mac:
            return None
        if self.is_randomized_mac(mac):
            return "Private / Randomized MAC (Android/iOS)"

        normalized = self.normalize_mac(mac)
        if not normalized or len(normalized) < 8:
            return None
        
        prefix = normalized[:8].upper()
        return self.oui_db.get(prefix, None)

    def classify_device(
        self,
        vendor: Optional[str],
        hostname: Optional[str],
        is_gateway: bool = False,
        is_host: bool = False
    ) -> str:
        """
        Infers a reasonable device category (Router, Computer, Mobile, Smart IoT, Printer, Generic).
        """
        if is_gateway:
            return "Router / Gateway"
        if is_host:
            return "This Host (Laptop)"

        v = (vendor or "").lower()
        h = (hostname or "").lower()

        if "randomized" in v or "android/ios" in v:
            return "Mobile Device (Private MAC)"
        if any(w in h for w in ["router", "gateway", "ap-", "modem", "hgu"]):
            return "Network Device"
        if any(w in v for w in ["tp-link", "d-link", "netgear", "cisco", "fiber", "dbc", "huawei"]):
            return "Network Device"
        if any(w in v for w in ["apple"]):
            if any(w in h for w in ["iphone", "ipad"]):
                return "Mobile (iOS)"
            if any(w in h for w in ["macbook", "imac", "mac"]):
                return "Computer (Mac)"
            return "Apple Device"
        if any(w in v for w in ["samsung", "xiaomi", "oneplus", "motorola", "google", "htc"]):
            return "Mobile / Smart Device"
        if any(w in v for w in ["espressif", "raspberry", "amazon"]):
            return "Smart Home / IoT"
        if any(w in v for w in ["intel", "dell", "realtek", "lenovo", "asus", "microsoft", "hp"]):
            return "PC / Workstation"
        if any(w in v or w in h for w in ["printer", "canon", "epson", "brother"]):
            return "Printer"

        return "Unclassified Device"

vendor_service = VendorService()
