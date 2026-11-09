"""Persistent local storage for Project LEO.
Uses only Python's standard library.
Database: memory/leo_memory.db
"""

import os
import sys
import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
MEMORY_DIR = BASE_DIR / "memory"
DB_PATH = MEMORY_DIR / "leo_memory.db"

def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()

class MemoryStore:
    def __init__(self, db_path=DB_PATH):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self):
        connection = sqlite3.connect(self.db_path, timeout=15)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        # Enable Write-Ahead Logging for high-concurrency read/write operations
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA synchronous = NORMAL")
        return connection

    def _initialize(self):
        with self._connect() as conn:
            cursor = conn.cursor()
            # 1. Message history
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS messages (
                    id TEXT PRIMARY KEY,
                    conversation_id TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    role TEXT NOT NULL,
                    content TEXT NOT NULL,
                    timestamp TEXT NOT NULL
                )
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_messages_conv_agent 
                ON messages(conversation_id, agent_id, timestamp)
            """)

            # 2. Key-value facts and long-term memory
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS memories (
                    id TEXT PRIMARY KEY,
                    key TEXT NOT NULL UNIQUE,
                    content TEXT NOT NULL,
                    category TEXT NOT NULL DEFAULT 'general',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
            """)

            # 3. Multi-agent task planning and execution
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS tasks (
                    id TEXT PRIMARY KEY,
                    description TEXT NOT NULL,
                    specialist TEXT NOT NULL,
                    depends_on TEXT DEFAULT '[]',
                    needs_approval INTEGER DEFAULT 0,
                    status TEXT DEFAULT 'pending',
                    result TEXT DEFAULT '',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_tasks_status 
                ON tasks(status)
            """)

            # 4. Enforced approval requests
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS approvals (
                    id TEXT PRIMARY KEY,
                    task_id TEXT,
                    action_type TEXT NOT NULL,
                    description TEXT NOT NULL,
                    requested_by TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'pending',
                    approved_by TEXT,
                    payload TEXT DEFAULT '{}',
                    created_at TEXT NOT NULL,
                    resolved_at TEXT
                )
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_approvals_status 
                ON approvals(status)
            """)

            # 5. Audit logs
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS audit_events (
                    id TEXT PRIMARY KEY,
                    event_type TEXT NOT NULL,
                    agent_id TEXT,
                    action TEXT NOT NULL,
                    details TEXT DEFAULT '',
                    status TEXT NOT NULL,
                    timestamp TEXT NOT NULL
                )
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_audit_timestamp 
                ON audit_events(timestamp DESC)
            """)
            conn.commit()

    # --- Conversation Message Operations ---
    def add_message(self, conversation_id: str, agent_id: str, role: str, content: str) -> dict:
        msg_id = str(uuid.uuid4())
        ts = now_utc()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO messages (id, conversation_id, agent_id, role, content, timestamp)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (msg_id, conversation_id, agent_id, role, content, ts)
            )
            conn.commit()
        return {
            "id": msg_id,
            "conversation_id": conversation_id,
            "agent_id": agent_id,
            "role": role,
            "content": content,
            "timestamp": ts
        }

    def get_history(self, conversation_id: str, agent_id: str = None) -> list:
        with self._connect() as conn:
            if agent_id:
                cursor = conn.execute(
                    """
                    SELECT id, conversation_id, agent_id, role, content, timestamp
                    FROM messages
                    WHERE conversation_id = ? AND agent_id = ?
                    ORDER BY timestamp ASC
                    """,
                    (conversation_id, agent_id)
                )
            else:
                cursor = conn.execute(
                    """
                    SELECT id, conversation_id, agent_id, role, content, timestamp
                    FROM messages
                    WHERE conversation_id = ?
                    ORDER BY timestamp ASC
                    """,
                    (conversation_id,)
                )
            return [dict(row) for row in cursor.fetchall()]

    def search_messages(self, query: str, conversation_id: str = None, limit: int = 20) -> list:
        with self._connect() as conn:
            pattern = f"%{query}%"
            if conversation_id:
                cursor = conn.execute(
                    """
                    SELECT id, conversation_id, agent_id, role, content, timestamp
                    FROM messages
                    WHERE conversation_id = ? AND content LIKE ?
                    ORDER BY timestamp DESC LIMIT ?
                    """,
                    (conversation_id, pattern, limit)
                )
            else:
                cursor = conn.execute(
                    """
                    SELECT id, conversation_id, agent_id, role, content, timestamp
                    FROM messages
                    WHERE content LIKE ?
                    ORDER BY timestamp DESC LIMIT ?
                    """,
                    (pattern, limit)
                )
            return [dict(row) for row in cursor.fetchall()]

    def clear_history(self, conversation_id: str, agent_id: str = None):
        with self._connect() as conn:
            if agent_id:
                conn.execute(
                    "DELETE FROM messages WHERE conversation_id = ? AND agent_id = ?",
                    (conversation_id, agent_id)
                )
            else:
                conn.execute(
                    "DELETE FROM messages WHERE conversation_id = ?",
                    (conversation_id,)
                )
            conn.commit()

    def list_conversations(self) -> list:
        with self._connect() as conn:
            cursor = conn.execute("""
                SELECT 
                    conversation_id, 
                    COUNT(*) as message_count,
                    MIN(timestamp) as started_at,
                    MAX(timestamp) as last_activity
                FROM messages
                GROUP BY conversation_id
                ORDER BY last_activity DESC
            """)
            return [dict(row) for row in cursor.fetchall()]

    # --- Explicit Facts / Memories ---
    def save_memory(self, key: str, content: str, category: str = "general") -> dict:
        mem_id = str(uuid.uuid4())
        ts = now_utc()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO memories (id, key, content, category, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET
                    content = excluded.content,
                    category = excluded.category,
                    updated_at = excluded.updated_at
                """,
                (mem_id, key, content, category, ts, ts)
            )
            conn.commit()
        return {"id": mem_id, "key": key, "content": content, "category": category, "updated_at": ts}

    def get_memory(self, key: str) -> dict:
        with self._connect() as conn:
            cursor = conn.execute("SELECT * FROM memories WHERE key = ?", (key,))
            row = cursor.fetchone()
            return dict(row) if row else None

    def search_memories(self, query: str, limit: int = 20) -> list:
        pattern = f"%{query}%"
        with self._connect() as conn:
            cursor = conn.execute(
                """
                SELECT * FROM memories 
                WHERE key LIKE ? OR content LIKE ? 
                ORDER BY updated_at DESC LIMIT ?
                """,
                (pattern, pattern, limit)
            )
            return [dict(row) for row in cursor.fetchall()]

    def list_memories(self, category: str = None) -> list:
        with self._connect() as conn:
            if category:
                cursor = conn.execute("SELECT * FROM memories WHERE category = ? ORDER BY key ASC", (category,))
            else:
                cursor = conn.execute("SELECT * FROM memories ORDER BY key ASC")
            return [dict(row) for row in cursor.fetchall()]

    # --- Task Records & Dependency Resolution ---
    def create_task(self, description: str, specialist: str, depends_on: list = None, needs_approval: bool = False, task_id: str = None) -> dict:
        t_id = task_id or f"task-{uuid.uuid4().hex[:8]}"
        deps_json = json.dumps(depends_on or [])
        ts = now_utc()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO tasks (id, description, specialist, depends_on, needs_approval, status, result, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, 'pending', '', ?, ?)
                """,
                (t_id, description, specialist, deps_json, 1 if needs_approval else 0, ts, ts)
            )
            conn.commit()
        return {
            "id": t_id,
            "description": description,
            "specialist": specialist,
            "depends_on": depends_on or [],
            "needs_approval": needs_approval,
            "status": "pending",
            "result": "",
            "created_at": ts,
            "updated_at": ts
        }

    def update_task(self, task_id: str, status: str = None, result: str = None) -> dict:
        ts = now_utc()
        with self._connect() as conn:
            if status is not None and result is not None:
                conn.execute(
                    "UPDATE tasks SET status = ?, result = ?, updated_at = ? WHERE id = ?",
                    (status, result, ts, task_id)
                )
            elif status is not None:
                conn.execute(
                    "UPDATE tasks SET status = ?, updated_at = ? WHERE id = ?",
                    (status, ts, task_id)
                )
            elif result is not None:
                conn.execute(
                    "UPDATE tasks SET result = ?, updated_at = ? WHERE id = ?",
                    (result, ts, task_id)
                )
            conn.commit()
        return self.get_task(task_id)

    def get_task(self, task_id: str) -> dict:
        with self._connect() as conn:
            cursor = conn.execute("SELECT * FROM tasks WHERE id = ?", (task_id,))
            row = cursor.fetchone()
            if not row:
                return None
            data = dict(row)
            data["depends_on"] = json.loads(data["depends_on"])
            data["needs_approval"] = bool(data["needs_approval"])
            return data

    def list_tasks(self, status: str = None) -> list:
        with self._connect() as conn:
            if status:
                cursor = conn.execute("SELECT * FROM tasks WHERE status = ? ORDER BY created_at ASC", (status,))
            else:
                cursor = conn.execute("SELECT * FROM tasks ORDER BY created_at ASC")
            results = []
            for row in cursor.fetchall():
                data = dict(row)
                data["depends_on"] = json.loads(data["depends_on"])
                data["needs_approval"] = bool(data["needs_approval"])
                results.append(data)
            return results

    def get_ready_tasks(self) -> list:
        """Returns all pending tasks whose dependencies are completely satisfied (marked 'done')."""
        all_tasks = {t["id"]: t for t in self.list_tasks()}
        ready = []
        for t in all_tasks.values():
            if t["status"] != "pending":
                continue
            deps = t.get("depends_on", [])
            if all(dep in all_tasks and all_tasks[dep]["status"] == "done" for dep in deps):
                ready.append(t)
        return ready

    def count_tasks(self) -> int:
        with self._connect() as conn:
            cursor = conn.execute("SELECT COUNT(*) FROM tasks")
            return cursor.fetchone()[0]

    # --- Approval Gate Management ---
    def create_approval(self, action_type: str, description: str, requested_by: str, task_id: str = None, payload: dict = None) -> dict:
        approval_id = f"appr-{uuid.uuid4().hex[:8]}"
        ts = now_utc()
        payload_str = json.dumps(payload or {})
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO approvals (id, task_id, action_type, description, requested_by, status, approved_by, payload, created_at, resolved_at)
                VALUES (?, ?, ?, ?, ?, 'pending', NULL, ?, ?, NULL)
                """,
                (approval_id, task_id, action_type, description, requested_by, payload_str, ts)
            )
            conn.commit()
        return {
            "id": approval_id,
            "task_id": task_id,
            "action_type": action_type,
            "description": description,
            "requested_by": requested_by,
            "status": "pending",
            "payload": payload or {},
            "created_at": ts
        }

    def resolve_approval(self, approval_id: str, approved: bool, approved_by: str = "user") -> dict:
        status = "approved" if approved else "rejected"
        ts = now_utc()
        with self._connect() as conn:
            conn.execute(
                """
                UPDATE approvals 
                SET status = ?, approved_by = ?, resolved_at = ?
                WHERE id = ? AND status = 'pending'
                """,
                (status, approved_by, ts, approval_id)
            )
            conn.commit()
        return self.get_approval(approval_id)

    def get_approval(self, approval_id: str) -> dict:
        with self._connect() as conn:
            cursor = conn.execute("SELECT * FROM approvals WHERE id = ?", (approval_id,))
            row = cursor.fetchone()
            if not row:
                return None
            data = dict(row)
            data["payload"] = json.loads(data["payload"])
            return data

    def list_pending_approvals(self) -> list:
        with self._connect() as conn:
            cursor = conn.execute("SELECT * FROM approvals WHERE status = 'pending' ORDER BY created_at ASC")
            results = []
            for row in cursor.fetchall():
                data = dict(row)
                data["payload"] = json.loads(data["payload"])
                results.append(data)
            return results

    # --- Audit Event Logging ---
    def log_audit_event(self, event_type: str, action: str, agent_id: str = None, details: str = "", status: str = "logged") -> dict:
        event_id = str(uuid.uuid4())
        ts = now_utc()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO audit_events (id, event_type, agent_id, action, details, status, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (event_id, event_type, agent_id, action, details, status, ts)
            )
            conn.commit()
        return {
            "id": event_id,
            "event_type": event_type,
            "agent_id": agent_id,
            "action": action,
            "details": details,
            "status": status,
            "timestamp": ts
        }

    def list_audit_events(self, limit: int = 50) -> list:
        with self._connect() as conn:
            cursor = conn.execute("SELECT * FROM audit_events ORDER BY timestamp DESC LIMIT ?", (limit,))
            return [dict(row) for row in cursor.fetchall()]

    # --- Statistics ---
    def get_stats(self) -> dict:
        with self._connect() as conn:
            m_count = conn.execute("SELECT COUNT(*) FROM messages").fetchone()[0]
            mem_count = conn.execute("SELECT COUNT(*) FROM memories").fetchone()[0]
            t_count = conn.execute("SELECT COUNT(*) FROM tasks").fetchone()[0]
            a_count = conn.execute("SELECT COUNT(*) FROM approvals WHERE status = 'pending'").fetchone()[0]
            size_bytes = self.db_path.stat().st_size if self.db_path.exists() else 0
            return {
                "messages": m_count,
                "memories": mem_count,
                "tasks": t_count,
                "pending_approvals": a_count,
                "db_size_bytes": size_bytes
            }

if __name__ == "__main__":
    store = MemoryStore()
    tasks_count = store.count_tasks()
    print("LEO persistent storage initialized.")
    print(f"Database: {store.db_path.resolve()}")
    print("Tables: messages, memories, tasks, audit_events")
    print(f"Existing tasks: {tasks_count}")
