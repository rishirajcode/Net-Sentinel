import sqlite3
import shutil
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Any
from app.config import DB_PATH, DATA_DIR

logger = logging.getLogger("netsentinel.database")

def get_db_connection() -> sqlite3.Connection:
    """Returns a SQLite connection with row factory enabled."""
    conn = sqlite3.connect(str(DB_PATH), timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn

def init_db() -> None:
    """Initializes tables and indexes."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with get_db_connection() as conn:
        cursor = conn.cursor()
        
        # Devices table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL,
                mac_address TEXT UNIQUE,
                hostname TEXT,
                custom_name TEXT,
                vendor TEXT,
                device_type TEXT DEFAULT 'Unclassified Device',
                status TEXT DEFAULT 'online', -- 'online', 'offline', 'unknown'
                classification TEXT DEFAULT 'unknown', -- 'trusted', 'unknown'
                notes TEXT,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                block_status TEXT DEFAULT 'unblocked', -- 'unblocked', 'blocked', 'manual_rule'
                is_gateway INTEGER DEFAULT 0,
                is_host INTEGER DEFAULT 0
            );
        """)

        # Scans table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                start_time TEXT NOT NULL,
                end_time TEXT,
                subnet TEXT NOT NULL,
                engine_used TEXT NOT NULL,
                devices_found INTEGER DEFAULT 0,
                new_devices INTEGER DEFAULT 0,
                offline_devices INTEGER DEFAULT 0,
                status TEXT DEFAULT 'running', -- 'completed', 'failed', 'running'
                error_message TEXT
            );
        """)

        # Device observations (historical records per scan)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS device_observations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id INTEGER NOT NULL,
                scan_id INTEGER,
                ip_address TEXT NOT NULL,
                mac_address TEXT,
                hostname TEXT,
                response_time_ms REAL,
                timestamp TEXT NOT NULL,
                FOREIGN KEY (device_id) REFERENCES devices (id) ON DELETE CASCADE,
                FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE SET NULL
            );
        """)

        # Router rules history
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS router_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                mac_address TEXT NOT NULL,
                ip_address TEXT,
                action TEXT NOT NULL, -- 'block', 'unblock'
                status TEXT NOT NULL, -- 'submitted', 'verified', 'manual_required', 'failed'
                rule_type TEXT DEFAULT 'denylist',
                details TEXT,
                timestamp TEXT NOT NULL
            );
        """)

        # Audit logs table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                action TEXT NOT NULL,
                actor TEXT DEFAULT 'admin',
                target TEXT,
                details TEXT,
                success INTEGER DEFAULT 1
            );
        """)

        # Users table (for admin authentication)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                created_at TEXT NOT NULL,
                last_login TEXT
            );
        """)

        # App settings key-value table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS app_settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
        """)

        # Indexes for fast lookup
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_devices_mac ON devices(mac_address);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_devices_ip ON devices(ip_address);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_observations_dev ON device_observations(device_id);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_logs(timestamp);")
        
        conn.commit()
    logger.info("Database initialized successfully at %s", DB_PATH)

def backup_database() -> Path:
    """Creates a timestamped backup of the SQLite database."""
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    backup_file = DATA_DIR / f"netsentinel_backup_{timestamp}.db"
    with get_db_connection() as conn:
        conn.commit()
    shutil.copy2(DB_PATH, backup_file)
    return backup_file

def restore_database(backup_file: Path) -> bool:
    """Restores database from backup file safely."""
    if not backup_file.exists():
        return False
    # Verify it is a valid SQLite DB
    try:
        conn = sqlite3.connect(str(backup_file))
        conn.execute("SELECT count(*) FROM devices;").fetchone()
        conn.close()
    except Exception:
        return False
    
    shutil.copy2(backup_file, DB_PATH)
    return True

def get_setting(key: str, default: Optional[str] = None) -> Optional[str]:
    with get_db_connection() as conn:
        row = conn.execute("SELECT value FROM app_settings WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else default

def set_setting(key: str, value: str) -> None:
    now = datetime.now(timezone.utc).isoformat()
    with get_db_connection() as conn:
        conn.execute("""
            INSERT INTO app_settings (key, value, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
        """, (key, value, now))
        conn.commit()
