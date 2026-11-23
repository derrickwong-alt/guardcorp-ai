import sqlite3
from datetime import datetime

class GuardCorpEngine:
    """Runtime Security Engine for One-Person Company AI Agents."""
    def __init__(self, db_path="guardcorp.db"):
        self.conn = sqlite3.connect(db_path)
        self._init_db()

    def _init_db(self):
        with self.conn:
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS security_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    event_type TEXT,
                    threat_level TEXT,
                    details TEXT
                )
            """)

    def audit_rag_payload(self, text: str) -> dict:
        blacklist = ["ignore previous instructions", "system prompt", "exfiltrate", "admin override"]
        detected = any(pattern in text.lower() for pattern in blacklist)
        status = "BLOCKED" if detected else "PASSED"
        
        self.log_event("RAG_AUDIT", "HIGH" if detected else "LOW", f"Payload check: {status}")
        return {"status": status, "threat_detected": detected}

    def log_event(self, event_type: str, threat_level: str, details: str):
        with self.conn:
            self.conn.execute(
                "INSERT INTO security_events (timestamp, event_type, threat_level, details) VALUES (?, ?, ?, ?)",
                (datetime.utcnow().isoformat(), event_type, threat_level, details)
            )

if __name__ == "__main__":
    engine = GuardCorpEngine()
    print("[GuardCorp AI] Security Engine active. Performing test scan...")
    result = engine.audit_rag_payload("Verify standard financial metrics.")
    print(f"[Scan Result]: {result}")