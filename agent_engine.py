import os
import sys
import json
from pathlib import Path
import requests

# Ensure utf-8 console output for emojis on Windows
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

BASE_DIR = Path(__file__).resolve().parent
CONFIG_PATH = BASE_DIR / "agents.json"
MODEL = os.getenv("LEO_MODEL", "qwen2.5:7b")
OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434").rstrip("/")
OLLAMA_URL = f"{OLLAMA_HOST}/api/chat"
CONVERSATION_ID = "leo-interactive-session"

# ANSI terminal colors
USE_COLOR = sys.stdout.isatty() and os.name == "nt" or sys.stdout.isatty()
CYAN = "\033[96m" if USE_COLOR else ""
GREEN = "\033[92m" if USE_COLOR else ""
YELLOW = "\033[93m" if USE_COLOR else ""
DIM = "\033[90m" if USE_COLOR else ""
RESET = "\033[0m" if USE_COLOR else ""
BOLD = "\033[1m" if USE_COLOR else ""

if not CONFIG_PATH.exists():
    print(f"Error: Configuration file not found at {CONFIG_PATH}")
    sys.exit(1)

with CONFIG_PATH.open("r", encoding="utf-8") as file:
    CONFIG = json.load(file)

DEFAULTS = CONFIG.get("defaults", {})
AGENTS = CONFIG.get("agents", {})

if len(AGENTS) != 6:
    raise ValueError(f"Expected 6 agents, found {len(AGENTS)}")

SHARED_RULES = "\n".join(
    f"- {rule}" for rule in DEFAULTS.get("shared_rules", [])
)

# Connect persistent memory, approval gate, quality gate, and orchestrator modules
from memory_store import MemoryStore
from approval_manager import ApprovalManager, ApprovalError
from quality_gate import QualityGate
from orchestrator import Orchestrator, OrchestratorError

store = MemoryStore()
approval_mgr = ApprovalManager(store=store)
quality_gate = QualityGate()

# Every agent has its own independent in-memory conversation history
histories = {}

def build_system_prompt(agent_cfg: dict) -> str:
    prompt = agent_cfg["system_prompt"]
    output_format = agent_cfg.get("output_format")
    fmt_str = ""
    if output_format:
        fmt_str = "\nRequired Output Sections:\n" + "\n".join(f"- {f}" for f in output_format)
    return f"{prompt}\n{fmt_str}\n\nShared Governance Rules:\n{SHARED_RULES}"

def reset_agent(agent_id: str) -> None:
    agent_cfg = AGENTS[agent_id]
    histories[agent_id] = [
        {"role": "system", "content": build_system_prompt(agent_cfg)}
    ]
    # Optionally reload persistent history from disk
    saved_history = store.get_history(CONVERSATION_ID, agent_id)
    for m in saved_history:
        if m["role"] in ("user", "assistant"):
            histories[agent_id].append({"role": m["role"], "content": m["content"]})

# Initialize all agent conversation histories
for agent_id in AGENTS:
    reset_agent(agent_id)

active_agent_id = "coordinator"

def ask_agent(agent_id: str, prompt: str, persist: bool = True) -> str:
    """Streams response from local Ollama model in real-time and persists messages to SQLite."""
    if agent_id not in AGENTS:
        err = f"Unknown agent: '{agent_id}'. Valid IDs: {', '.join(AGENTS.keys())}"
        print(f"{YELLOW}{err}{RESET}")
        return err

    agent_cfg = AGENTS[agent_id]
    name = agent_cfg.get("name", agent_id)
    icon = agent_cfg.get("icon", "🤖")
    temp = agent_cfg.get("temperature", 0.5)

    histories[agent_id].append({"role": "user", "content": prompt})
    if persist:
        store.add_message(CONVERSATION_ID, agent_id, "user", prompt)

    full_response = []

    try:
        response = requests.post(
            OLLAMA_URL,
            json={
                "model": MODEL,
                "messages": histories[agent_id],
                "options": {
                    "temperature": temp
                },
                "stream": True
            },
            stream=True,
            timeout=180
        )

        if response.status_code != 200:
            histories[agent_id].pop()
            err_msg = f"Error from Ollama ({response.status_code}): {response.text}"
            print(f"\n{YELLOW}{err_msg}{RESET}")
            return err_msg

        print(f"\n{CYAN}{BOLD}{icon} {name}:{RESET}\n", flush=True)

        for line in response.iter_lines():
            if line:
                chunk = json.loads(line.decode("utf-8"))
                token = chunk.get("message", {}).get("content", "")
                if token:
                    print(token, end="", flush=True)
                    full_response.append(token)

        print()
        response_text = "".join(full_response)
        histories[agent_id].append({"role": "assistant", "content": response_text})
        if persist:
            store.add_message(CONVERSATION_ID, agent_id, "assistant", response_text)
        return response_text

    except KeyboardInterrupt:
        print(f"\n{YELLOW}[Response interrupted by user]{RESET}")
        if full_response:
            partial_text = "".join(full_response)
            histories[agent_id].append({"role": "assistant", "content": partial_text})
            if persist:
                store.add_message(CONVERSATION_ID, agent_id, "assistant", partial_text)
            return partial_text
        else:
            histories[agent_id].pop()
            return "[Interrupted before output]"

    except requests.exceptions.ConnectionError:
        histories[agent_id].pop()
        err_conn = (
            f"Cannot connect to Ollama at {OLLAMA_HOST}.\n"
            f"Ensure Ollama is running ('ollama serve' or start the Ollama desktop app)."
        )
        print(f"\n{YELLOW}{err_conn}{RESET}")
        return err_conn
    except Exception as e:
        histories[agent_id].pop()
        print(f"\n{YELLOW}Unexpected error: {e}{RESET}")
        return f"Unexpected error: {e}"

def agent_runner_callback(specialist: str, prompt: str, task: dict) -> str:
    """Adapter callback linking orchestrator execution back to local streaming agent execution."""
    return ask_agent(specialist, prompt, persist=True)

# Attach runner callback and quality gate to orchestrator
orchestrator = Orchestrator(
    store=store,
    approval_manager=approval_mgr,
    agent_runner=agent_runner_callback,
    quality_gate=quality_gate
)

def list_agents():
    print(f"\n{BOLD}Available Agents ({len(AGENTS)} loaded):{RESET}")
    for a_id, cfg in AGENTS.items():
        active_marker = f"{GREEN}● active{RESET}" if a_id == active_agent_id else ""
        icon = cfg.get("icon", "🤖")
        name = cfg.get("name", a_id)
        temp = cfg.get("temperature", 0.7)
        desc = cfg.get("description", "")
        print(f"  {icon} {BOLD}{name}{RESET} [{a_id}] (temp: {temp}) {active_marker}")
        print(f"     {DIM}{desc}{RESET}")
    print()

def print_help():
    print(f"\n{BOLD}Engine Commands:{RESET}")
    print(f"  {CYAN}/agents{RESET}              - List all 6 agents and active selection")
    print(f"  {CYAN}/use <agent_id>{RESET}      - Switch the active conversational agent")
    print(f"  {CYAN}/ask <agent_id> <msg>{RESET} - Ask a specific agent without switching active agent")
    print(f"  {CYAN}/pipeline <goal>{RESET}      - Run end-to-end multi-agent pipeline with handoffs")
    print(f"  {CYAN}/board{RESET}                - View orchestrator task board")
    print(f"  {CYAN}/quality{RESET}              - View pipeline quality gate audit report")
    print(f"  {CYAN}/run{RESET}                  - Run all pending ready tasks")
    print(f"  {CYAN}/approvals{RESET}            - List pending authorization requests")
    print(f"  {CYAN}/approve <appr_id>{RESET}    - Approve a pending authorization request")
    print(f"  {CYAN}/reject <appr_id>{RESET}     - Reject a pending authorization request")
    print(f"  {CYAN}/history{RESET}              - Display history message counts across agents")
    print(f"  {CYAN}/stats{RESET}                - Show database and memory statistics")
    print(f"  {CYAN}/reset{RESET}                - Reset current active agent's conversation history")
    print(f"  {CYAN}/reset all{RESET}            - Reset conversation history for all 6 agents")
    print(f"  {CYAN}/help{RESET}                 - Show this menu")
    print(f"  {CYAN}/exit{RESET}                 - Exit LEO engine\n")

def execute_pipeline(goal: str):
    """Executes a complete 5-stage pipeline: Architect -> Builder -> Reviewer -> QA -> Release Manager."""
    print(f"\n{BOLD}Initiating Multi-Agent Pipeline for Goal:{RESET} {CYAN}{goal}{RESET}")
    
    # 1. Register linear dependency pipeline
    steps = [
        ("architect", f"Analyze requirements and design system architecture blueprint for: {goal}"),
        ("builder", f"Produce implementation code and instructions based on the architect's approved blueprint for: {goal}"),
        ("reviewer", f"Audit the builder's implementation for correctness, security, and edge cases for: {goal}"),
        ("qa", f"Formulate test matrix and evaluate test coverage for: {goal}"),
        ("release_manager", f"Assess release readiness and prepare deployment verification checklist for: {goal}", True)
    ]
    
    tasks = orchestrator.create_pipeline(steps)
    print(f"{GREEN}Created {len(tasks)} dependency-linked tasks across specialist agents.{RESET}")
    print(orchestrator.format_board())
    
    print(f"\n{BOLD}Executing pipeline with contextual handoffs...{RESET}")
    run_summary = orchestrator.run_until_complete()
    print(f"\n{BOLD}Execution Pass Complete:{RESET}")
    print(orchestrator.format_board())
    
    # Check if Quality Gate blocked the release
    failed_gates = [t for t in orchestrator.list_tasks() if t.get("status") == "quality_gate_failed"]
    if failed_gates:
        print(f"\n{YELLOW}{BOLD}[QUALITY GATE TRIGGERED]: Release blocked due to unresolved defects or failing tests.{RESET}")
        for fg in failed_gates:
            print(f"  {fg['specialist'].upper()} Task [{fg['id']}]:\n  {fg.get('result', '')}")

    pending = approval_mgr.list_pending()
    if pending:
        print(f"\n{YELLOW}{BOLD}Action Paused at Approval Gate:{RESET}")
        for appr in pending:
            print(approval_mgr.format_approval_card(appr))
        print(f"\nType {CYAN}/approve <id>{RESET} to grant permission or {CYAN}/reject <id>{RESET} to cancel.")

def main():
    global active_agent_id

    if os.name == "nt":
        os.system("")

    print("=" * 60)
    print(f"{BOLD}LEO - Multi-Agent Engine (v{CONFIG.get('version', '1.0')}){RESET}")
    print(f"Agents loaded: {GREEN}{len(AGENTS)}{RESET}")
    print(f"Storage: {GREEN}SQLite (leo_memory.db){RESET} | WAL Mode: Active")
    print(f"Approval Gates: {GREEN}Enforced{RESET} | Orchestrator: {GREEN}Ready{RESET}")
    print(f"Model: {GREEN}{MODEL}{RESET} | Endpoint: {OLLAMA_HOST}")
    print(f"Default Agent: {CYAN}{AGENTS[active_agent_id]['name']} {AGENTS[active_agent_id]['icon']}{RESET}")
    print(f"Type {CYAN}/help{RESET} for commands or {CYAN}/exit{RESET} to quit.")
    print("=" * 60)

    while True:
        current_cfg = AGENTS[active_agent_id]
        prompt_label = f"\n{BOLD}[{current_cfg['icon']} {current_cfg['role']}] You:{RESET} "

        try:
            user_input = input(prompt_label).strip()
        except (EOFError, KeyboardInterrupt):
            print("\nLEO Engine: Goodbye!")
            break

        if not user_input:
            continue

        cmd = user_input.lower()
        if cmd in ("/exit", "/quit"):
            print("LEO Engine: Goodbye!")
            break

        if cmd == "/help":
            print_help()
            continue

        if cmd == "/agents":
            list_agents()
            continue

        if cmd.startswith("/use"):
            parts = user_input.split(maxsplit=1)
            if len(parts) < 2:
                print(f"{YELLOW}Usage: /use <agent_id> (e.g. /use architect){RESET}")
                continue
            target_id = parts[1].strip().lower()
            if target_id in AGENTS:
                active_agent_id = target_id
                target_cfg = AGENTS[active_agent_id]
                print(f"{GREEN}Switched active agent to: {target_cfg['icon']} {target_cfg['name']}{RESET}")
            else:
                print(f"{YELLOW}Unknown agent '{target_id}'. Valid IDs: {', '.join(AGENTS.keys())}{RESET}")
            continue

        if cmd.startswith("/ask"):
            parts = user_input.split(maxsplit=2)
            if len(parts) < 3:
                print(f"{YELLOW}Usage: /ask <agent_id> <message>{RESET}")
                continue
            target_id = parts[1].strip().lower()
            agent_prompt = parts[2].strip()
            if target_id not in AGENTS:
                print(f"{YELLOW}Unknown agent '{target_id}'. Valid IDs: {', '.join(AGENTS.keys())}{RESET}")
                continue
            ask_agent(target_id, agent_prompt)
            continue

        if cmd.startswith("/pipeline"):
            parts = user_input.split(maxsplit=1)
            if len(parts) < 2:
                print(f"{YELLOW}Usage: /pipeline <goal description>{RESET}")
                continue
            execute_pipeline(parts[1].strip())
            continue

        if cmd in ("/board", "/tasks"):
            print()
            print(orchestrator.format_board())
            continue

        if cmd == "/run":
            print(f"\n{BOLD}Running ready tasks...{RESET}")
            results = orchestrator.run_ready_tasks()
            print(f"Executed: {len(results)} tasks")
            print(orchestrator.format_board())
            continue

        if cmd == "/approvals":
            pending = approval_mgr.list_pending()
            print(f"\n{BOLD}Pending Approvals ({len(pending)}):{RESET}")
            for a in pending:
                print(approval_mgr.format_approval_card(a))
            if not pending:
                print("No pending approvals.")
            continue

        if cmd.startswith("/approve"):
            parts = user_input.split(maxsplit=1)
            if len(parts) < 2:
                print(f"{YELLOW}Usage: /approve <approval_id>{RESET}")
                continue
            a_id = parts[1].strip()
            try:
                approval_mgr.decide(a_id, True)
                print(f"{GREEN}Approved request [{a_id}]. Resuming pipeline execution...{RESET}")
                results = orchestrator.run_ready_tasks(approval_map={
                    appr["payload"].get("task_id", ""): a_id for appr in [approval_mgr.get_approval(a_id)] if appr
                })
                print(orchestrator.format_board())
            except Exception as e:
                print(f"{YELLOW}Approval error: {e}{RESET}")
            continue

        if cmd.startswith("/reject"):
            parts = user_input.split(maxsplit=1)
            if len(parts) < 2:
                print(f"{YELLOW}Usage: /reject <approval_id>{RESET}")
                continue
            a_id = parts[1].strip()
            try:
                approval_mgr.decide(a_id, False)
                print(f"{YELLOW}Rejected request [{a_id}].{RESET}")
            except Exception as e:
                print(f"{YELLOW}Error: {e}{RESET}")
            continue

        if cmd == "/stats":
            stats = store.get_stats()
            print(f"\n{BOLD}LEO System Statistics:{RESET}")
            print(f"  Messages Stored:     {stats['messages']}")
            print(f"  Explicit Memories:   {stats['memories']}")
            print(f"  Total Tasks:         {stats['tasks']}")
            print(f"  Pending Approvals:   {stats['pending_approvals']}")
            print(f"  Database File Size:  {stats['db_size_bytes']} bytes")
            continue

        if cmd == "/quality":
            readiness = orchestrator.quality_gate.check_pipeline_readiness(store.list_tasks())
            print(f"\n{BOLD}Pipeline Quality Gate Audit:{RESET}")
            status_color = GREEN if readiness["is_ready_for_release"] else YELLOW
            print(f"  Release Ready: {status_color}{readiness['is_ready_for_release']}{RESET}")
            if readiness["blockers"]:
                print(f"  {YELLOW}Blockers Detected:{RESET}")
                for b in readiness["blockers"]:
                    print(f"    - {b}")
            if readiness.get("reviewer_report"):
                rev = readiness["reviewer_report"]
                print(f"  Reviewer Verdict: {rev['verdict']} (Critical: {rev['critical_count']})")
            if readiness.get("qa_report"):
                qa = readiness["qa_report"]
                print(f"  QA Tests Outcome: {'PASSED' if qa['passed'] else 'FAILED'} (Failures: {qa['failure_count']})")
            continue

        if cmd == "/reset":
            reset_agent(active_agent_id)
            print(f"{GREEN}Conversation context for {AGENTS[active_agent_id]['name']} cleared.{RESET}")
            continue

        if cmd == "/reset all":
            for a_id in AGENTS:
                reset_agent(a_id)
            print(f"{GREEN}Conversation contexts for all 6 agents cleared.{RESET}")
            continue

        if cmd == "/history":
            print(f"\n{BOLD}Agent Context Histories:{RESET}")
            for a_id, msgs in histories.items():
                u_count = sum(1 for m in msgs if m["role"] == "user")
                a_count = sum(1 for m in msgs if m["role"] == "assistant")
                icon = AGENTS[a_id]["icon"]
                print(f"  {icon} {AGENTS[a_id]['name']}: {len(msgs)} messages ({u_count} user turns, {a_count} responses)")
            print()
            continue

        # Regular message to active agent
        ask_agent(active_agent_id, user_input)

if __name__ == "__main__":
    main()
