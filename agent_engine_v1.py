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

# Every agent has its own independent conversation history.
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

# Initialize all agent conversation histories
for agent_id in AGENTS:
    reset_agent(agent_id)

active_agent_id = "coordinator"

def list_agents():
    print(f"\n{BOLD}Available Agents ({len(AGENTS)} loaded):{RESET}")
    for a_id, cfg in AGENTS.items():
        active_marker = f"{GREEN}● active{RESET}" if a_id == active_agent_id else ""
        icon = cfg.get("icon", "🤖")
        name = cfg.get("name", a_id)
        role = cfg.get("role", "")
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
    print(f"  {CYAN}/reset{RESET}               - Reset current active agent's conversation history")
    print(f"  {CYAN}/reset all{RESET}           - Reset conversation history for all 6 agents")
    print(f"  {CYAN}/history{RESET}             - Display history message counts across agents")
    print(f"  {CYAN}/help{RESET}                - Show this menu")
    print(f"  {CYAN}/exit{RESET}                - Exit LEO engine\n")

def ask_agent(agent_id: str, prompt: str) -> None:
    if agent_id not in AGENTS:
        print(f"{YELLOW}Unknown agent: '{agent_id}'. Type /agents to view available IDs.{RESET}")
        return

    agent_cfg = AGENTS[agent_id]
    name = agent_cfg.get("name", agent_id)
    icon = agent_cfg.get("icon", "🤖")
    temp = agent_cfg.get("temperature", 0.5)

    histories[agent_id].append({"role": "user", "content": prompt})
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
            print(f"\n{YELLOW}Error from Ollama ({response.status_code}): {response.text}{RESET}")
            return

        print(f"\n{CYAN}{BOLD}{icon} {name}:{RESET}\n", flush=True)

        for line in response.iter_lines():
            if line:
                chunk = json.loads(line.decode("utf-8"))
                token = chunk.get("message", {}).get("content", "")
                if token:
                    print(token, end="", flush=True)
                    full_response.append(token)

        print()
        histories[agent_id].append({"role": "assistant", "content": "".join(full_response)})

    except KeyboardInterrupt:
        print(f"\n{YELLOW}[Response interrupted by user]{RESET}")
        if full_response:
            histories[agent_id].append({"role": "assistant", "content": "".join(full_response)})
        else:
            histories[agent_id].pop()

    except requests.exceptions.ConnectionError:
        histories[agent_id].pop()
        print(
            f"\n{YELLOW}Cannot connect to Ollama at {OLLAMA_HOST}.\n"
            f"Ensure Ollama is running ('ollama serve' or start the Ollama desktop app).{RESET}"
        )
    except Exception as e:
        histories[agent_id].pop()
        print(f"\n{YELLOW}Unexpected error: {e}{RESET}")

def main():
    global active_agent_id

    if os.name == "nt":
        os.system("")

    print("=" * 60)
    print(f"{BOLD}LEO - Multi-Agent Engine (v{CONFIG.get('version', '1.0')}){RESET}")
    print(f"Agents loaded: {GREEN}{len(AGENTS)}{RESET}")
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
