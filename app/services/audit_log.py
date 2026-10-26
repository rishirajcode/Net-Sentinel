import logging
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from app.database import get_db_connection

logger = logging.getLogger("netsentinel.audit")

class AuditLogService:
    @staticmethod
    def log_event(
        action: str,
        actor: str = "admin",
        target: Optional[str] = None,
        details: Optional[str] = None,
        success: bool = True
    ) -> None:
        """
        Record a security-sensitive or operational action to persistent SQLite audit log.
        No passwords, session tokens, or router secrets are ever stored.
        """
        now_iso = datetime.now(timezone.utc).isoformat()
        try:
            with get_db_connection() as conn:
                conn.execute("""
                    INSERT INTO audit_logs (timestamp, action, actor, target, details, success)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (now_iso, action, actor, target, details, 1 if success else 0))
                conn.commit()
            logger.info("AUDIT [%s] Actor=%s Target=%s Success=%s", action, actor, target, success)
        except Exception as e:
            logger.error("Failed to write audit log: %s", e)

    @staticmethod
    def get_logs(limit: int = 100, action_filter: Optional[str] = None) -> List[Dict[str, Any]]:
        query = "SELECT * FROM audit_logs WHERE 1=1"
        params: List[Any] = []
        if action_filter:
            query += " AND action = ?"
            params.append(action_filter)
        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)

        with get_db_connection() as conn:
            rows = conn.execute(query, params).fetchall()
            return [dict(r) for r in rows]

audit_logger = AuditLogService()
