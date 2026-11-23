import sqlite3
import logging
from datetime import datetime
from typing import Dict, Any, List

logging.basicConfig(level=logging.INFO, format="%(asctime)s - [AIRCopilot] - %(levelname)s - %(message)s")

class AIRCopilot:
    """
    Autonomous AI Incident Response (AIR) Copilot.
    Monitors system audit logs in SQLite, evaluates threat escalation,
    and executes containment protocols (e.g. simulated container isolation `docker pause`, API token revocation).
    """

    def __init__(self, db_path: str = "guardcorp.db"):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS incident_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    event_type TEXT,
                    threat_level TEXT,
                    source_agent TEXT,
                    details TEXT,
                    containment_action TEXT
                )
            """)

    def record_incident(self, event_type: str, threat_level: str, source_agent: str, details: str) -> Dict[str, Any]:
        """
        Logs an incident and triggers automated containment if threat level is HIGH or CRITICAL.
        """
        containment_action = "NONE"
        
        if threat_level.upper() in ["HIGH", "CRITICAL"]:
            containment_action = self._trigger_containment(source_agent, threat_level)

        timestamp = datetime.utcnow().isoformat()
        
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """INSERT INTO incident_logs 
                   (timestamp, event_type, threat_level, source_agent, details, containment_action)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (timestamp, event_type, threat_level, source_agent, details, containment_action)
            )

        logging.info(f"Incident recorded: [{threat_level}] {event_type} from {source_agent}. Action: {containment_action}")
        
        return {
            "timestamp": timestamp,
            "event_type": event_type,
            "threat_level": threat_level,
            "source_agent": source_agent,
            "containment_action": containment_action,
            "status": "CONTAINED" if containment_action != "NONE" else "LOGGED"
        }

    def _trigger_containment(self, source_agent: str, threat_level: str) -> str:
        """Executes automated containment procedures."""
        if threat_level.upper() == "CRITICAL":
            action = f"EXEC_DOCKER_PAUSE({source_agent}); REVOKE_API_KEY({source_agent});"
            logging.critical(f"AUTOMATED CONTAINMENT EXECUTED: Isolated container for '{source_agent}' and revoked keys!")
        else:
            action = f"SUSPEND_TOOL_PERMISSIONS({source_agent}); NOTIFY_FOUNDER;"
            logging.warning(f"AUTOMATED CONTAINMENT EXECUTED: Suspended tool permissions for '{source_agent}'.")
        return action

    def get_recent_incidents(self, limit: int = 10) -> List[Dict[str, Any]]:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT timestamp, event_type, threat_level, source_agent, details, containment_action FROM incident_logs ORDER BY id DESC LIMIT ?", (limit,))
            rows = cursor.fetchall()
            return [
                {
                    "timestamp": r[0], "event_type": r[1], "threat_level": r[2],
                    "source_agent": r[3], "details": r[4], "containment_action": r[5]
                }
                for r in rows
            ]

if __name__ == "__main__":
    copilot = AIRCopilot("test_guardcorp.db")
    res = copilot.record_incident("RAG_POISON_DETECTED", "CRITICAL", "WorkerAgent_01", "Indirect prompt injection attempt in RAG vector payload.")
    print("Incident Record:", res)
    print("Recent Incidents:", copilot.get_recent_incidents(1))
