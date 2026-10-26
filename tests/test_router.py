import pytest
from app.services.router_adapter import RouterService, MockRouterAdapter, DbcHguAdapter

def test_mock_router_block_and_unblock():
    service = RouterService()
    service.set_mock_mode(True)

    # Test confirmation required
    res_unconfirmed = service.block_device(
        mac_address="00:11:22:33:44:55",
        ip_address="192.168.1.150",
        confirmed=False
    )
    assert res_unconfirmed["success"] is False
    assert "Explicit user confirmation is required" in res_unconfirmed["error"]

    # Test confirmed block
    res_blocked = service.block_device(
        mac_address="00:11:22:33:44:55",
        ip_address="192.168.1.150",
        confirmed=True
    )
    assert res_blocked["success"] is True

    # Test active rules contains this rule
    active = service.adapter.get_active_rules()
    assert any(r["mac_address"] == "00:11:22:33:44:55" for r in active)

    # Test unblock
    res_unblocked = service.unblock_device(
        mac_address="00:11:22:33:44:55",
        confirmed=True
    )
    assert res_unblocked["success"] is True

def test_safety_guards_prevent_blocking_gateway_and_host():
    service = RouterService()
    service.set_mock_mode(True)

    # Attempt to block Gateway (192.168.1.1)
    res_gw = service.block_device(
        mac_address="4c:ae:1c:48:f3:0e",
        ip_address="192.168.1.1",
        confirmed=True
    )
    assert res_gw["success"] is False
    assert "Cannot block the default gateway router" in res_gw["error"]

    # Attempt to block Host Laptop (192.168.1.38)
    res_host = service.block_device(
        mac_address="74:40:bb:68:d7:b5",
        ip_address="192.168.1.38",
        confirmed=True
    )
    assert res_host["success"] is False
    assert "Cannot block the host" in res_host["error"]

def test_dbc_adapter_guided_integrity():
    adapter = DbcHguAdapter()
    caps = adapter.inspect_capabilities("192.168.1.1")
    assert caps["model"] == "DBC HGU-V210-4AC"
    # Never falsely advertise automated API
    assert caps["automated_api_verified"] is False
