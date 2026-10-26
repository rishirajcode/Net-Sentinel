import pytest
from app.models import ScanTriggerRequest, DeviceBase, DeviceUpdate

def test_scan_trigger_request_valid_subnets():
    req1 = ScanTriggerRequest(subnet="192.168.1.0/24")
    assert req1.subnet == "192.168.1.0/24"

    req2 = ScanTriggerRequest(subnet="10.0.0.0/24")
    assert req2.subnet == "10.0.0.0/24"

    req3 = ScanTriggerRequest(subnet="172.16.5.0/24")
    assert req3.subnet == "172.16.5.0/24"

def test_scan_trigger_request_rejects_public_internet():
    with pytest.raises(ValueError, match="Only RFC 1918 private subnets are permitted"):
        ScanTriggerRequest(subnet="8.8.8.0/24")

    with pytest.raises(ValueError, match="Only RFC 1918 private subnets are permitted"):
        ScanTriggerRequest(subnet="1.1.1.0/24")

def test_scan_trigger_request_rejects_overly_broad_subnets():
    with pytest.raises(ValueError, match="Subnet range too broad"):
        ScanTriggerRequest(subnet="10.0.0.0/8")

def test_device_base_model():
    dev = DeviceBase(
        ip_address="192.168.1.50",
        mac_address="00:11:22:33:44:55",
        hostname="my-laptop"
    )
    assert dev.ip_address == "192.168.1.50"
    assert dev.classification == "unknown"
