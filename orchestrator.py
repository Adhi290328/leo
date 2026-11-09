"""Project LEO task orchestrator.
Coordinates specialist agents through a supplied Python callback.
Enforces dependency trees, approval gates, and contextual result handoffs.
It does not execute shell commands or write arbitrary files without explicit authorization.
"""

import os
import sys
import json
from pathlib import Path
from memory_store import MemoryStore, now_utc
from approval_manager import ApprovalManager, ApprovalError
from quality_gate import QualityGate

VALID_AGENTS = {
    "coordinator",
    "architect",
    "builder",
    "reviewer",
    "qa",
    "release_manager",
}

class OrchestratorError(Exception):
    """Raised for invalid orchestration requests, cyclic dependencies, or security blocks."""
    pass

class Orchestrator:
    def __init__(
        self,
        store: MemoryStore = None,
        approval_manager: ApprovalManager = None,
        agent_runner = None,
        quality_gate: QualityGate = None
    ):
        self.store = store or MemoryStore()
        self.approvals = approval_manager or ApprovalManager(self.store)
        self.agent_runner = agent_runner
        self.quality_gate = quality_gate or QualityGate()

    def get_summary(self) -> dict:
        """Returns high-level status of tasks, approval gates, and registered agents."""
        tasks = self.store.list_tasks()
        pending_approvals = self.approvals.list_pending()
        status_counts = {}
        for t in tasks:
            status = t.get("status", "unknown")
            status_counts[status] = status_counts.get(status, 0) + 1

        return {
            "total_tasks": len(tasks),
            "status_breakdown": status_counts,
            "pending_approvals": len(pending_approvals),
            "registered_agents": sorted(list(VALID_AGENTS))
        }

    def _check_cycle(self, new_task_id: str, depends_on: list) -> None:
        """Ensures that adding dependencies does not introduce cyclic deadlocks."""
        visited = set()
        stack = list(depends_on)

        while stack:
            curr_id = stack.pop()
            if curr_id == new_task_id:
                raise OrchestratorError(f"Cyclic dependency detected: task '{new_task_id}' cannot depend on itself or its descendants.")
            if curr_id in visited:
                continue
            visited.add(curr_id)
            dep_task = self.store.get_task(curr_id)
            if dep_task:
                stack.extend(dep_task.get("depends_on", []))

    def create_task(
        self,
        description: str,
        specialist: str,
        depends_on: list = None,
        needs_approval: bool = False,
        task_id: str = None
    ) -> dict:
        """Creates a new task assigned to a designated specialist, validating dependencies."""
        if specialist not in VALID_AGENTS:
            raise OrchestratorError(f"Invalid specialist '{specialist}'. Valid agents: {', '.join(sorted(VALID_AGENTS))}")

        deps = list(depends_on or [])
        
        # Validate that all prerequisite tasks exist
        for dep_id in deps:
            dep_task = self.store.get_task(dep_id)
            if not dep_task:
                raise OrchestratorError(f"Prerequisite task '{dep_id}' does not exist.")

        # Check for circular dependencies
        if task_id:
            self._check_cycle(task_id, deps)

        task = self.store.create_task(
            description=description,
            specialist=specialist,
            depends_on=deps,
            needs_approval=needs_approval,
            task_id=task_id
        )

        self.store.log_audit_event(
            event_type="task_created",
            action="create_task",
            agent_id=specialist,
            details=json.dumps({"task_id": task["id"], "description": description}),
            status="pending"
        )
        return task

    def list_tasks(self, status: str = None) -> list:
        """Lists tasks, optionally filtered by status."""
        return self.store.list_tasks(status=status)

    def get_task(self, task_id: str) -> dict:
        """Gets full task details."""
        return self.store.get_task(task_id)

    def _build_contextual_prompt(self, task: dict) -> str:
        """
        Enriches the task description with the outputs of its prerequisite tasks (automated handoff).
        """
        base_desc = task["description"]
        deps = task.get("depends_on", [])
        if not deps:
            return base_desc

        prereq_blocks = []
        for dep_id in deps:
            dep_task = self.store.get_task(dep_id)
            if dep_task and dep_task.get("result"):
                prereq_blocks.append(
                    f"[Handoff from {dep_task['specialist'].upper()} (Task {dep_id})]:\n{dep_task['result']}"
                )

        if not prereq_blocks:
            return base_desc

        handoff_context = "\n\n".join(prereq_blocks)
        return (
            f"{base_desc}\n\n"
            f"=== CONTEXT FROM PREREQUISITE TASKS ===\n"
            f"{handoff_context}\n"
            f"========================================"
        )

    def run_task(self, task_id: str, approval_id: str = None) -> dict:
        """
        Executes a single task if prerequisites are satisfied and any required approvals are granted.
        Passes previous outputs automatically into the agent runner.
        """
        task = self.store.get_task(task_id)
        if not task:
            raise OrchestratorError(f"Task '{task_id}' not found.")

        if task["status"] == "done":
            return {"task_id": task_id, "status": "done", "result": task.get("result", "")}

        # 1. Enforce Dependency Prerequisites
        for dep_id in task.get("depends_on", []):
            dep_task = self.store.get_task(dep_id)
            if not dep_task or dep_task.get("status") != "done":
                raise OrchestratorError(
                    f"Action blocked: task '{task_id}' depends on '{dep_id}', which is not yet done."
                )

        # 2. Enforce Quality Gate on Release Stage
        if task.get("specialist") == "release_manager":
            readiness = self.quality_gate.check_pipeline_readiness(self.store.list_tasks())
            if not readiness["is_ready_for_release"]:
                block_note = "Quality Gate Failed:\n" + "\n".join(f"- {b}" for b in readiness["blockers"])
                self.store.update_task(task_id, status="quality_gate_failed", result=block_note)
                raise OrchestratorError(f"Action blocked: task '{task_id}' failed quality gate.\n{block_note}")

        # 3. Enforce Approval Gate
        if task.get("needs_approval"):
            action_type = f"execute_task_{task['specialist']}"
            payload = {"task_id": task_id}

            if not approval_id:
                # Register a pending approval ticket if none exists
                pending = [
                    a for a in self.approvals.list_pending()
                    if a.get("task_id") == task_id or (isinstance(a.get("payload"), dict) and a.get("payload", {}).get("task_id") == task_id)
                ]
                if not pending:
                    appr = self.approvals.request_approval(
                        action_type=action_type,
                        description=f"Approval to execute task '{task_id}': {task['description'][:60]}",
                        requested_by=task["specialist"],
                        task_id=task_id,
                        payload=payload
                    )
                    appr_note = f"Registered pending approval ticket: {appr['id']}"
                else:
                    appr_note = f"Awaiting decision on approval ticket: {pending[0]['id']}"

                self.store.update_task(task_id, status="blocked", result=appr_note)
                raise OrchestratorError(
                    f"Action blocked: task '{task_id}' requires explicit approval before execution. {appr_note}"
                )

            # Atomically authorize & consume approval
            self.approvals.authorize_once(approval_id, action_type=action_type, payload=payload)

        # 4. Transition to in_progress
        self.store.update_task(task_id, status="in_progress")
        self.store.log_audit_event(
            event_type="task_started",
            action="execute",
            agent_id=task["specialist"],
            details=json.dumps({"task_id": task_id}),
            status="in_progress"
        )

        # 5. Formulate contextual prompt with prerequisite handoffs
        enriched_prompt = self._build_contextual_prompt(task)

        # 6. Execute via agent runner callback
        try:
            if callable(self.agent_runner):
                result = self.agent_runner(task["specialist"], enriched_prompt, task)
            else:
                result = f"Task completed by {task['specialist']} (no runner attached)."

            self.store.update_task(task_id, status="done", result=str(result))
            self.store.log_audit_event(
                event_type="task_completed",
                action="execute",
                agent_id=task["specialist"],
                details=json.dumps({"task_id": task_id}),
                status="done"
            )
            return {"task_id": task_id, "status": "done", "result": str(result)}

        except Exception as exc:
            err_msg = f"Task execution failed: {exc}"
            self.store.update_task(task_id, status="failed", result=err_msg)
            self.store.log_audit_event(
                event_type="task_failed",
                action="execute",
                agent_id=task["specialist"],
                details=json.dumps({"task_id": task_id, "error": str(exc)}),
                status="failed"
            )
            raise OrchestratorError(err_msg) from exc

    def run_ready_tasks(self, approval_map: dict = None) -> list:
        """
        Scans for all pending tasks whose dependencies are satisfied and executes them.
        Returns a list of outcome dictionaries: [{'task_id': ..., 'status': ..., 'result': ...}]
        """
        approval_map = approval_map or {}
        ready = self.store.get_ready_tasks()
        results = []

        for task in ready:
            task_id = task["id"]

            # Enforce Quality Gate on Release Stage
            if task.get("specialist") == "release_manager":
                readiness = self.quality_gate.check_pipeline_readiness(self.store.list_tasks())
                if not readiness["is_ready_for_release"]:
                    block_note = "Quality Gate Failed:\n" + "\n".join(f"- {b}" for b in readiness["blockers"])
                    self.store.update_task(task_id, status="quality_gate_failed", result=block_note)
                    results.append({
                        "task_id": task_id,
                        "status": "quality_gate_failed",
                        "result": block_note
                    })
                    continue

            if task.get("needs_approval"):
                appr_id = approval_map.get(task_id)
                if not appr_id:
                    action_type = f"execute_task_{task['specialist']}"
                    # Check or create pending approval
                    pending = [
                        a for a in self.approvals.list_pending()
                        if a.get("task_id") == task_id or (isinstance(a.get("payload"), dict) and a.get("payload", {}).get("task_id") == task_id)
                    ]
                    if not pending:
                        appr = self.approvals.request_approval(
                            action_type=action_type,
                            description=f"Approval to execute task '{task_id}': {task['description'][:60]}",
                            requested_by=task["specialist"],
                            task_id=task_id,
                            payload={"task_id": task_id}
                        )
                        appr_id_str = appr["id"]
                    else:
                        appr_id_str = pending[0]["id"]

                    self.store.update_task(task_id, status="blocked", result=f"Pending approval ticket {appr_id_str}")
                    results.append({
                        "task_id": task_id,
                        "status": "blocked",
                        "result": f"Requires user approval ({appr_id_str})"
                    })
                    continue
            else:
                appr_id = None

            outcome = self.run_task(task_id, approval_id=appr_id)
            results.append(outcome)

        return results

    def run_until_complete(self, max_passes: int = 10, approval_map: dict = None) -> dict:
        """
        Loops through ready tasks across multiple passes until all are done or blocked on approval.
        """
        passes = 0
        executed_tasks = []

        while passes < max_passes:
            passes += 1
            ready = self.store.get_ready_tasks()
            if not ready:
                break
            outcomes = self.run_ready_tasks(approval_map=approval_map)
            executed_tasks.extend(outcomes)
            # If all outcomes in this pass are blocked, stop looping
            if all(o["status"] == "blocked" for o in outcomes):
                break

        return {
            "passes": passes,
            "executed_count": len(executed_tasks),
            "summary": self.get_summary()
        }

    def create_pipeline(self, steps: list) -> list:
        """
        Helper to construct a linear chain of dependent tasks.
        steps format: [('architect', 'Plan system'), ('builder', 'Implement plan'), ...]
        """
        created = []
        prev_id = None
        for item in steps:
            if len(item) == 2:
                specialist, desc = item
                needs_appr = False
            else:
                specialist, desc, needs_appr = item

            deps = [prev_id] if prev_id else []
            t = self.create_task(
                description=desc,
                specialist=specialist,
                depends_on=deps,
                needs_approval=needs_appr
            )
            created.append(t)
            prev_id = t["id"]
        return created

    def format_board(self) -> str:
        """Renders an ASCII Kanban-style task status board."""
        tasks = self.store.list_tasks()
        if not tasks:
            return "No tasks recorded."

        status_symbols = {
            "done": "[DONE]",
            "in_progress": "[RUNNING]",
            "pending": "[PENDING]",
            "blocked": "[BLOCKED]",
            "failed": "[FAILED]",
            "quality_gate_failed": "[GATE_FAIL]"
        }

        lines = [
            "+-----------------------------------------------------------------------------+",
            "| LEO Orchestrator Task Board                                                 |",
            "+-----------------------------------------------------------------------------+"
        ]
        for t in tasks:
            t_id = t["id"]
            sym = status_symbols.get(t["status"], f"[{t['status'].upper()}]")
            spec = t["specialist"]
            desc = t["description"][:45] + ("..." if len(t["description"]) > 45 else "")
            appr = " [NEEDS APPROVAL]" if t.get("needs_approval") else ""
            deps = f" (deps: {', '.join(t.get('depends_on', []))})" if t.get("depends_on") else ""
            lines.append(f"| {sym:<10} {t_id:<14} {spec:<14} {desc}{appr}{deps}")
        lines.append("+-----------------------------------------------------------------------------+")
        return "\n".join(lines)

if __name__ == "__main__":
    orch = Orchestrator()
    summary = orch.get_summary()
    print("LEO Task Orchestrator initialized.")
    print(f"Summary: {summary}")
    print("\nCurrent Board:")
    print(orch.format_board())
