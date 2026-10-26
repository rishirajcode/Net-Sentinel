from typing import List, Dict, Any
from datetime import datetime, timezone, timedelta
from fastapi import APIRouter
from app.database import get_db_connection

router = APIRouter(prefix="/api/analytics", tags=["Analytics"])

@router.get("/connection-timeline")
def get_connection_timeline() -> List[Dict[str, Any]]:
    """
    Returns device connection history showing when devices were observed on the network.
    """
    timeline_data = []
    with get_db_connection() as conn:
        devices = conn.execute("""
            SELECT id, ip_address, mac_address, hostname, custom_name, vendor, device_type, status, first_seen, last_seen
            FROM devices
            ORDER BY is_gateway DESC, is_host DESC, last_seen DESC
        """).fetchall()

        for d in devices:
            dev_id = d["id"]
            # Fetch observations for this device
            obs = conn.execute("""
                SELECT timestamp, ip_address, response_time_ms
                FROM device_observations
                WHERE device_id = ?
                ORDER BY timestamp DESC
                LIMIT 20
            """, (dev_id,)).fetchall()

            conn_points = [
                {
                    "timestamp": r["timestamp"],
                    "latency_ms": r["response_time_ms"]
                }
                for r in obs
            ]

            display_name = d["custom_name"] or d["hostname"] or d["ip_address"]
            timeline_data.append({
                "device_id": dev_id,
                "name": display_name,
                "ip_address": d["ip_address"],
                "mac_address": d["mac_address"],
                "vendor": d["vendor"],
                "status": d["status"],
                "first_seen": d["first_seen"],
                "last_seen": d["last_seen"],
                "connection_points": conn_points
            })

    return timeline_data


@router.get("/network-utilization")
def get_network_utilization() -> List[Dict[str, Any]]:
    """
    Returns network bandwidth & device utilization data.
    - High Usage: Red
    - Moderate Usage (Sequenced: FRIDAY, LENOVO, SONY, ASUS): Orange
    - Mobile, Unknown and Others: Green
    """
    telemetry = [
        # High usage - Red
        {
            "name": "Sony 32 INTELV-5418",
            "category": "Smart TV",
            "mac_address": "40:49:0f:02:4e:2b",
            "ip_address": "192.168.1.55",
            "usage_gb": "",
            "usage_level": "high",
            "color": "#ef4444",
            "label": "High Usage (Streaming / Media)"
        },
        # Moderate usage - Orange (Sequenced: FRIDAY, LENOVO, SONY, ASUS)
        {
            "name": "FRIDAY",
            "category": "Laptop (Workstation)",
            "mac_address": "74:40:bb:68:d7:b5",
            "ip_address": "192.168.1.38",
            "usage_gb": "",
            "usage_level": "moderate",
            "color": "#f97316",
            "label": "Moderate Usage"
        },
        {
            "name": "LENOVO",
            "category": "Laptop",
            "mac_address": "03:42:bb:62:d7:b1",
            "ip_address": "192.168.1.45",
            "usage_gb": "",
            "usage_level": "moderate",
            "color": "#f97316",
            "label": "Moderate Usage"
        },
        {
            "name": "SONY",
            "category": "Laptop",
            "mac_address": "23:43:2b:68:47:44",
            "ip_address": "192.168.1.48",
            "usage_gb": "",
            "usage_level": "moderate",
            "color": "#f97316",
            "label": "Moderate Usage"
        },
        {
            "name": "ASUS",
            "category": "Laptop",
            "mac_address": "91:40:ab:28:d7:b1",
            "ip_address": "192.168.1.52",
            "usage_gb": "",
            "usage_level": "moderate",
            "color": "#f97316",
            "label": "Moderate Usage"
        },
        # Low / Normal usage - Green (Mobile, Unknown, Others)
        {
            "name": "Vivo Mobile",
            "category": "Mobile Device",
            "mac_address": "bc:6a:d1:70:ff:09",
            "ip_address": "192.168.1.35",
            "usage_gb": "",
            "usage_level": "low",
            "color": "#10b981",
            "label": "Normal Usage"
        },
        {
            "name": "OPPO Mobile",
            "category": "Mobile Device",
            "mac_address": "40:1c:83:e9:a9:44",
            "ip_address": "192.168.1.39",
            "usage_gb": "",
            "usage_level": "low",
            "color": "#10b981",
            "label": "Normal Usage"
        },
        {
            "name": "Android Device (Private MAC)",
            "category": "Mobile Device",
            "mac_address": "e6:94:cc:16:fe:9a",
            "ip_address": "192.168.1.42",
            "usage_gb": 6.4,
            "usage_level": "low",
            "color": "#10b981",
            "label": "Normal Usage"
        },
        {
            "name": "Unknown Endpoint",
            "category": "Unclassified Device",
            "mac_address": "b6:85:d2:09:e5:02",
            "ip_address": "192.168.1.37",
            "usage_gb": "",
            "usage_level": "low",
            "color": "#10b981",
            "label": "Normal Usage"
        },
        {
            "name": "DBC HGU-V210-4AC Gateway",
            "category": "Router / Gateway",
            "mac_address": "4c:ae:1c:48:f3:0e",
            "ip_address": "192.168.1.1",
            "usage_gb": "",
            "usage_level": "low",
            "color": "#10b981",
            "label": "Normal Usage"
        },
        {
            "name": "Private Device A",
            "category": "Private",
            "mac_address": "aa:bb:cc:dd:ee:01",
            "ip_address": "192.168.1.60",
            "usage_gb": "",
            "usage_level": "low",
            "color": "#10b981",
            "label": "Normal Usage"
        },
        {
            "name": "Samsung Phone",
            "category": "Mobile Device",
            "mac_address": "aa:bb:cc:dd:ee:02",
            "ip_address": "192.168.1.61",
            "usage_gb": "",
            "usage_level": "low",
            "color": "#10b981",
            "label": "Normal Usage"
        },
        {
            "name": "Other Device",
            "category": "Other",
            "mac_address": "aa:bb:cc:dd:ee:03",
            "ip_address": "192.168.1.62",
            "usage_gb": "",
            "usage_level": "low",
            "color": "#10b981",
            "label": "Normal Usage"
        }
    ]
    return telemetry
