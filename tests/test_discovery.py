import pytest
from app.services.vendor import VendorService
from app.services.discovery import DiscoveredHost

def test_mac_normalization():
    # Various formats
    assert VendorService.normalize_mac("74-40-bb-68-d7-b5") == "74:40:bb:68:d7:b5"
    assert VendorService.normalize_mac("7440BB68D7B5") == "74:40:bb:68:d7:b5"
    assert VendorService.normalize_mac("74:40:BB:68:D7:B5") == "74:40:bb:68:d7:b5"
    assert VendorService.normalize_mac(None) is None

def test_vendor_lookup():
    v = VendorService()
    # Realtek
    assert "Realtek" in (v.lookup_vendor("74:40:bb:68:d7:b5") or "")
    # DBC / Fiber
    assert "DBC" in (v.lookup_vendor("4c:ae:1c:48:f3:0e") or "")
    # Apple
    assert "Apple" in (v.lookup_vendor("18:65:90:00:11:22") or "")
    # Unknown Universally Administered MAC
    assert v.lookup_vendor("00:00:01:00:00:00") is None
    # Randomized / Locally Administered MAC (bit 1 of octet 0 set)
    assert "Randomized" in (v.lookup_vendor("02:00:00:00:00:00") or "")

def test_device_classification():
    v = VendorService()
    # Gateway
    assert v.classify_device(vendor=None, hostname=None, is_gateway=True) == "Router / Gateway"
    # Host
    assert v.classify_device(vendor=None, hostname=None, is_host=True) == "This Host (Laptop)"
    # Apple phone
    assert "Mobile" in v.classify_device(vendor="Apple, Inc.", hostname="Johns-iPhone")
    # Smart device
    assert "Smart" in v.classify_device(vendor="Espressif Inc.", hostname=None)
