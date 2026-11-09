"""Approval enforcement layer for Project LEO.
Ensures actions require human approval and cannot be bypassed by agent instructions.
"""

import os
import sys
import json
from pathlib import Path
from datetime import datetime, timezone, timedelta
from memory_store import MemoryStore, now_utc

class ApprovalError(Exception):
    """Raised when an unapproved, mismatched, expired, or already-consumed action attempts to execute."""
    pass

class ApprovalManager:
    APPROVAL_REQUIRED_ACTIONS = {
        "write_files",
        "run_commands",
        "deploy",
        "publish",
        "delete_data"
    }

    # Default TTL: approvals expire after 1 hour unless overridden
    DEFAULT_TTL_SECONDS = 3600

    def __init__(self, store: MemoryStore = None, agents_config_path: Path = None):
        self.store = store or MemoryStore()
        self._load_approval_actions(agents_config_path)

    def _load_approval_actions(self, config_path: Path = None):
        cfg_path = config_path or Path(__file__).resolve().parent / "agents.json"
        if cfg_path.exists():
            try:
                with cfg_path.open("r", encoding="utf-8") as f:
                    cfg = json.load(f)
                    defaults = cfg.get("defaults", {})
                    actions = defaults.get("approval_required_actions", [])
                    if actions:
                        self.APPROVAL_REQUIRED_ACTIONS = set(actions)
            except Exception:
                pass

    def is_approval_required(self, action_type: str) -> bool:
        """Checks if a specified action requires explicit user authorization."""
        return action_type in self.APPROVAL_REQUIRED_ACTIONS

    def list_pending(self) -> list:
        """Returns all approval requests currently awaiting user decision."""
        return self.store.list_pending_approvals()

    def get_approval(self, approval_id: str) -> dict:
        """Retrieves details for a specific approval ID."""
        return self.store.get_approval(approval_id)

    def request_approval(
        self,
        action_type: str,
        description: str,
        requested_by: str,
        task_id: str = None,
        payload: dict = None,
        ttl_seconds: int = None
    ) -> dict:
        """Registers a pending approval request with optional expiration and logs an audit trail."""
        effective_payload = dict(payload or {})
        ttl = ttl_seconds or self.DEFAULT_TTL_SECONDS
        
        # Stamp expiration into metadata if not provided
        if "_expires_at" not in effective_payload:
            expires_dt = datetime.now(timezone.utc) + timedelta(seconds=ttl)
            effective_payload["_expires_at"] = expires_dt.isoformat()

        approval = self.store.create_approval(
            action_type=action_type,
            description=description,
            requested_by=requested_by,
            task_id=task_id,
            payload=effective_payload
        )
        self.store.log_audit_event(
            event_type="approval_requested",
            action=action_type,
            agent_id=requested_by,
            details=json.dumps({"approval_id": approval["id"], "description": description}),
            status="pending"
        )
        return approval

    def decide(self, approval_id: str, approved: bool, decided_by: str = "user") -> dict:
        """Explicitly approves or rejects a pending request. Only application/user can invoke this."""
        appr = self.get_approval(approval_id)
        if not appr:
            raise ApprovalError(f"Approval request '{approval_id}' not found.")
        if appr["status"] != "pending":
            raise ApprovalError(f"Approval '{approval_id}' is already {appr['status']}.")

        updated = self.store.resolve_approval(approval_id, approved, decided_by)
        self.store.log_audit_event(
            event_type="approval_decided",
            action=updated["action_type"],
            agent_id=decided_by,
            details=json.dumps({"approval_id": approval_id, "approved": approved}),
            status=updated["status"]
        )
        return updated

    def revoke(self, approval_id: str, reason: str = "Revoked by user", decided_by: str = "user") -> dict:
        """Revokes a pending approval request."""
        appr = self.get_approval(approval_id)
        if not appr:
            raise ApprovalError(f"Approval request '{approval_id}' not found.")
        if appr["status"] != "pending":
            raise ApprovalError(f"Cannot revoke approval '{approval_id}'; currently '{appr['status']}'.")

        updated = self.store.resolve_approval(approval_id, False, decided_by)
        self.store.log_audit_event(
            event_type="approval_revoked",
            action=updated["action_type"],
            agent_id=decided_by,
            details=json.dumps({"approval_id": approval_id, "reason": reason}),
            status="rejected"
        )
        return updated

    def authorize_once(self, approval_id: str, action_type: str, payload: dict = None) -> bool:
        """
        Atomically validates and consumes an approval ticket.
        Guarantees that an approved action:
        1. Is genuinely approved (not pending, rejected, or expired).
        2. Matches the exact action_type and payload parameters.
        3. Can only ever be executed ONCE (status transitions to 'consumed').
        """
        with self.store._connect() as conn:
            cursor = conn.execute(
                "SELECT * FROM approvals WHERE id = ?",
                (approval_id,)
            )
            row = cursor.fetchone()

            if not row:
                raise ApprovalError("Action blocked: approval does not exist.")

            status = row["status"]
            if status == "pending":
                raise ApprovalError("Action blocked: approval is still pending.")
            if status == "rejected":
                raise ApprovalError("Action blocked: approval was rejected.")
            if status == "consumed":
                raise ApprovalError("Action blocked: approval was already consumed.")
            if status != "approved":
                raise ApprovalError(f"Action blocked: approval is in invalid status '{status}'.")

            if row["action_type"] != action_type:
                raise ApprovalError("Action blocked: action type does not match approval.")

            try:
                stored_payload_raw = json.loads(row["payload"] or "{}")
            except (TypeError, ValueError, json.JSONDecodeError) as exc:
                conn.rollback()
                raise ApprovalError(
                    "Action blocked: stored approval payload is invalid."
                ) from exc

            # Check expiration TTL if present
            expires_at_str = stored_payload_raw.get("_expires_at")
            if expires_at_str:
                try:
                    expires_dt = datetime.fromisoformat(expires_at_str)
                    if datetime.now(timezone.utc) > expires_dt:
                        conn.rollback()
                        raise ApprovalError("Action blocked: approval ticket has expired.")
                except Exception as ex:
                    if isinstance(ex, ApprovalError):
                        raise ex

            # Prepare normalized payloads for comparison (ignoring internal _expires_at metadata)
            clean_stored = {k: v for k, v in stored_payload_raw.items() if not k.startswith("_")}
            clean_expected = {k: v for k, v in (payload or {}).items() if not k.startswith("_")}

            approved_normalized = json.dumps(
                clean_stored,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False
            )
            expected_normalized = json.dumps(
                clean_expected,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False
            )

            if approved_normalized != expected_normalized:
                conn.rollback()
                raise ApprovalError(
                    "Action blocked: action details do not match approval."
                )

            # Atomically consume the approval ticket
            update_cursor = conn.execute(
                """
                UPDATE approvals
                SET status = 'consumed', resolved_at = ?
                WHERE id = ? AND status = 'approved'
                """,
                (now_utc(), approval_id),
            )

            if update_cursor.rowcount != 1:
                conn.rollback()
                raise ApprovalError(
                    "Action blocked: approval was already consumed."
                )

            conn.commit()

        self.store.log_audit_event(
            event_type="approval_consumed",
            action=action_type,
            agent_id="approval_manager",
            details=json.dumps({"approval_id": approval_id}, ensure_ascii=False),
            status="authorized",
        )
        return True

    def format_approval_card(self, approval: dict) -> str:
        """Formats an approval request into a user-friendly terminal card."""
        a_id = approval.get("id")
        action = approval.get("action_type")
        desc = approval.get("description")
        req_by = approval.get("requested_by")
        status = approval.get("status")
        payload = approval.get("payload", {})
        clean_p = {k: v for k, v in payload.items() if not k.startswith("_")}
        
        lines = [
            f"+-- Approval Request [{a_id}] " + ("-" * 28),
            f"| Action:       {action}",
            f"| Description:  {desc}",
            f"| Requested by: {req_by}",
            f"| Status:       {status}",
        ]
        if clean_p:
            lines.append(f"| Parameters:   {json.dumps(clean_p)}")
        lines.append("+" + ("-" * 54))
        return "\n".join(lines)

    def get_summary(self) -> dict:
        """Returns counts of approvals grouped by their status."""
        with self.store._connect() as conn:
            cursor = conn.execute("""
                SELECT status, COUNT(*) as count 
                FROM approvals 
                GROUP BY status
            """)
            counts = {row["status"]: row["count"] for row in cursor.fetchall()}
            return {
                "pending": counts.get("pending", 0),
                "approved": counts.get("approved", 0),
                "consumed": counts.get("consumed", 0),
                "rejected": counts.get("rejected", 0)
            }

if __name__ == "__main__":
    mgr = ApprovalManager()
    summary = mgr.get_summary()
    print("LEO Approval Manager initialized.")
    print(f"Protected action types: {', '.join(sorted(mgr.APPROVAL_REQUIRED_ACTIONS))}")
    print(f"Approvals summary: {summary}")
