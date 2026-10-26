from pydantic import BaseModel, Field, field_validator
from typing import Optional, List
import ipaddress

class DeviceBase(BaseModel):
    ip_address: str
    mac_address: Optional[str] = None
    hostname: Optional[str] = None
    custom_name: Optional[str] = None
    vendor: Optional[str] = None
    device_type: Optional[str] = "Unclassified Device"
    classification: str = "unknown" # 'trusted', 'unknown'
    notes: Optional[str] = None

class DeviceUpdate(BaseModel):
    custom_name: Optional[str] = None
    classification: Optional[str] = None # 'trusted', 'unknown'
    notes: Optional[str] = None
    device_type: Optional[str] = None

class DeviceResponse(BaseModel):
    id: int
    ip_address: str
    mac_address: Optional[str] = None
    hostname: Optional[str] = None
    custom_name: Optional[str] = None
    vendor: Optional[str] = None
    device_type: str
    status: str # 'online', 'offline', 'unknown'
    classification: str # 'trusted', 'unknown'
    notes: Optional[str] = None
    first_seen: str
    last_seen: str
    block_status: str # 'unblocked', 'blocked', 'manual_rule'
    is_gateway: bool = False
    is_host: bool = False

class DeviceObservationResponse(BaseModel):
    id: int
    scan_id: Optional[int]
    ip_address: str
    mac_address: Optional[str]
    hostname: Optional[str]
    response_time_ms: Optional[float]
    timestamp: str

class DeviceDetailResponse(DeviceResponse):
    observations: List[DeviceObservationResponse] = []
    ip_history: List[str] = []

class ScanTriggerRequest(BaseModel):
    subnet: Optional[str] = None
    engine_preference: Optional[str] = "auto" # 'auto', 'native', 'nmap'

    @field_validator("subnet")
    @classmethod
    def validate_subnet(cls, v: Optional[str]) -> Optional[str]:
        if not v:
            return v
        try:
            net = ipaddress.IPv4Network(v, strict=False)
            if not net.is_private and not net.is_loopback:
                raise ValueError("Only RFC 1918 private subnets are permitted (e.g. 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12)")
            if net.num_addresses > 1024:
                raise ValueError("Subnet range too broad (maximum /22 or 1024 hosts allowed for safety)")
            return str(net)
        except Exception as e:
            raise ValueError(f"Invalid subnet format: {e}")

class ScanResponse(BaseModel):
    id: int
    start_time: str
    end_time: Optional[str]
    subnet: str
    engine_used: str
    devices_found: int
    new_devices: int
    offline_devices: int
    status: str
    error_message: Optional[str] = None

class DashboardSummary(BaseModel):
    total_discovered: int
    online_devices: int
    offline_devices: int
    trusted_devices: int
    unknown_devices: int
    blocked_devices: int
    most_recent_scan: Optional[ScanResponse] = None
    router_status: str = "Unavailable"
    router_model: str = "DBC HGU-V210-4AC"
    router_gateway: str = "192.168.1.1"
    nmap_installed: bool = False
    current_subnet: str = "192.168.1.0/24"
    host_ip: str = "127.0.0.1"

class RouterActionRequest(BaseModel):
    mac_address: str
    ip_address: Optional[str] = None
    device_name: Optional[str] = None
    confirmed: bool = False

class RouterStatusResponse(BaseModel):
    router_model: str
    gateway_ip: str
    connection_status: str # 'online', 'unreachable', 'auth_required'
    integration_mode: str # 'automated', 'manual', 'mock'
    capabilities: dict
    active_rules: List[dict] = []
    message: str

class AuditLogResponse(BaseModel):
    id: int
    timestamp: str
    action: str
    actor: str
    target: Optional[str]
    details: Optional[str]
    success: bool

class LoginRequest(BaseModel):
    username: str
    password: str

class RegisterRequest(BaseModel):
    username: str
    password: str

class SettingsUpdateRequest(BaseModel):
    router_gateway: Optional[str] = None
    subnet: Optional[str] = None
    scan_interval_minutes: Optional[int] = None
    lan_access_enabled: Optional[bool] = None
    router_username: Optional[str] = None
    router_password: Optional[str] = None
