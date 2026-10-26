import asyncio
import logging
import threading
import time
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from app.config import settings
from app.database import get_db_connection
from app.services.discovery import discovery_service
from app.services.audit_log import audit_logger

logger = logging.getLogger("netsentinel.monitoring")

class MonitoringService:
    def __init__(self):
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._interval_minutes = settings.SCAN_INTERVAL_MINUTES

    def start_background_monitoring(self) -> None:
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()
        logger.info("Background network monitoring started (Interval: %d min)", self._interval_minutes)

    def stop_background_monitoring(self) -> None:
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
        logger.info("Background network monitoring stopped.")

    def _run_loop(self) -> None:
        # Give initial server startup 10 seconds before first background scan
        time.sleep(10)
        while self._running:
            try:
                logger.info("Executing scheduled periodic network scan...")
                result = discovery_service.run_scan()
                if result.get("new_devices", 0) > 0:
                    audit_logger.log_event(
                        "NEW_DEVICE_ALERT",
                        actor="monitor",
                        details=f"Discovered {result['new_devices']} new device(s) on network!"
                    )
            except Exception as e:
                logger.error("Error in background scan: %s", e)

            # Sleep in 5 second increments to allow quick shutdown
            for _ in range(self._interval_minutes * 12):
                if not self._running:
                    break
                time.sleep(5)

    @staticmethod
    def get_recent_alerts(limit: int = 20) -> List[Dict[str, Any]]:
        with get_db_connection() as conn:
            rows = conn.execute("""
                SELECT * FROM audit_logs
                WHERE action IN ('NEW_DEVICE_ALERT', 'BLOCK_DEVICE', 'UNBLOCK_DEVICE', 'BLOCK_DEVICE_REFUSED', 'SCAN_COMPLETED')
                ORDER BY timestamp DESC
                LIMIT ?
            """, (limit,)).fetchall()
            return [dict(r) for r in rows]

monitoring_service = MonitoringService()
