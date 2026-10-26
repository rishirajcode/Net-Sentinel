import pytest
from app.main import get_dashboard_summary
from app.api.devices import list_devices, get_device, export_csv
from app.api.settings import get_app_settings
from app.api.auth import auth_status, hash_password, verify_password
from app.database import init_db
from app.services.router_adapter import router_service

@pytest.fixture(autouse=True)
def setup_db():
    init_db()
    router_service.set_mock_mode(True)

def test_index_page():
    from app.main import index_page
    from starlette.requests import Request
    scope = {"type": "http", "method": "GET", "path": "/", "headers": []}
    req = Request(scope)
    resp = index_page(req)
    assert resp.status_code == 200
    content = resp.body.decode("utf-8")
    assert "Net Sentinel" in content
    assert "Software Vantage" in content

def test_summary_handler():
    data = get_dashboard_summary()
    assert "total_discovered" in data
    assert "online_devices" in data
    assert "offline_devices" in data
    assert "trusted_devices" in data
    assert "unknown_devices" in data
    assert "blocked_devices" in data
    assert data["router_model"] == "DBC HGU-V210-4AC"

def test_devices_list_handler():
    devices = list_devices()
    assert isinstance(devices, list)
    if devices:
        dev = devices[0]
        assert "ip_address" in dev
        assert "status" in dev

def test_device_detail_handler():
    devices = list_devices()
    if devices:
        dev_id = devices[0]["id"]
        detail = get_device(dev_id)
        assert detail["id"] == dev_id
        assert "observations" in detail
        assert "ip_history" in detail

def test_csv_export_handler():
    res = export_csv()
    assert res.status_code == 200
    assert "text/csv" in res.media_type
    content = res.body.decode("utf-8")
    assert "ip_address,mac_address" in content

def test_settings_handler():
    data = get_app_settings()
    assert data["app_name"] == "Net Sentinel"
    assert data["developer"] == "Software Vantage"
    assert "current_subnet" in data
    assert "router_gateway" in data

def test_auth_status_handler(monkeypatch):
    class DummyRequest:
        cookies = {}
    class DummyResponse:
        def set_cookie(self, *args, **kwargs):
            pass
    
    res = auth_status(DummyRequest(), DummyResponse())
    assert "admin_exists" in res
    assert "authenticated" in res
    assert "csrf_token" in res
    assert res["csrf_token"] is not None

def test_connection_timeline_handler():
    from app.api.analytics import get_connection_timeline
    timeline = get_connection_timeline()
    assert isinstance(timeline, list)
    if timeline:
        first = timeline[0]
        assert "name" in first
        assert "first_seen" in first
        assert "last_seen" in first
        assert "connection_points" in first

def test_network_utilization_handler():
    from app.api.analytics import get_network_utilization
    telemetry = get_network_utilization()
    assert isinstance(telemetry, list)
    assert len(telemetry) >= 5

    # Check Sony 32 INTEL-5418 TV is high usage in red
    tv = next((x for x in telemetry if x["mac_address"] == "40:49:0f:02:4e:2b"), None)
    assert tv is not None
    assert tv["name"] == "Sony 32 INTEL-5418"
    assert tv["color"] == "#ef4444"
    assert tv["usage_level"] == "high"

    # Check Laptops: FRIDAY, LENOVO, SONY, ASUS in moderate usage orange sequence
    laptop_macs = ["74:40:bb:68:d7:b5", "03:42:bb:62:d7:b1", "23:43:2b:68:47:44", "91:40:ab:28:d7:b1"]
    laptops = [x for x in telemetry if x["mac_address"] in laptop_macs]
    assert len(laptops) == 4
    for lap in laptops:
        assert lap["color"] == "#f97316"
        assert lap["usage_level"] == "moderate"

    # Verify descending usage sequence
    laptop_usages = [lap["usage_gb"] for lap in laptops]
    assert laptop_usages == sorted(laptop_usages, reverse=True)

    # Check Mobile, Unknown and Others are green
    green_items = [x for x in telemetry if x["color"] == "#10b981"]
    assert len(green_items) >= 3
    for g in green_items:
        assert g["usage_level"] == "low"
