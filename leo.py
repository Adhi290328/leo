import os
import sys
import json
import requests

MODEL = os.getenv("LEO_MODEL", "qwen2.5:7b")
OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434").rstrip("/")
OLLAMA_URL = f"{OLLAMA_HOST}/api/chat"

SYSTEM_PROMPT = (
    "You are LEO, an intelligent, calm, logical, and friendly personal AI assistant. "
    "You communicate clearly, thoughtfully, and helpfully."
)

# ANSI terminal colors (gracefully supported in Windows Terminal / PowerShell)
USE_COLOR = sys.stdout.isatty() and os.name == "nt" or sys.stdout.isatty()
CYAN = "\033[96m" if USE_COLOR else ""
GREEN = "\033[92m" if USE_COLOR else ""
YELLOW = "\033[93m" if USE_COLOR else ""
DIM = "\033[90m" if USE_COLOR else ""
RESET = "\033[0m" if USE_COLOR else ""
BOLD = "\033[1m" if USE_COLOR else ""

messages = [
    {
        "role": "system",
        "content": SYSTEM_PROMPT
    }
]

def print_help():
    print(f"\n{BOLD}Available Commands:{RESET}")
    print(f"  {CYAN}/help{RESET}     - Show this help menu")
    print(f"  {CYAN}/reset{RESET}    - Clear the conversation memory")
    print(f"  {CYAN}/history{RESET}  - Show conversation message count")
    print(f"  {CYAN}/model{RESET}    - Show active model and connection details")
    print(f"  {CYAN}/exit{RESET}     - Exit LEO\n")

def ask_leo_stream(question: str) -> None:
    """Streams response from local Ollama model in real-time."""
    messages.append({"role": "user", "content": question})
    full_response = []

    try:
        response = requests.post(
            OLLAMA_URL,
            json={
                "model": MODEL,
                "messages": messages,
                "stream": True
            },
            stream=True,
            timeout=120
        )

        if response.status_code != 200:
            messages.pop()  # Rollback on error
            print(f"\n{YELLOW}Error from Ollama ({response.status_code}): {response.text}{RESET}")
            return

        print(f"{CYAN}{BOLD}LEO:{RESET} ", end="", flush=True)

        for line in response.iter_lines():
            if line:
                chunk = json.loads(line.decode("utf-8"))
                token = chunk.get("message", {}).get("content", "")
                if token:
                    print(token, end="", flush=True)
                    full_response.append(token)

        print()  # New line after completion
        messages.append({"role": "assistant", "content": "".join(full_response)})

    except KeyboardInterrupt:
        # Gracefully handle Ctrl+C during streaming generation
        print(f"\n{YELLOW}[Response paused by user]{RESET}")
        if full_response:
            messages.append({"role": "assistant", "content": "".join(full_response)})
        else:
            messages.pop()

    except requests.exceptions.ConnectionError:
        messages.pop()  # Rollback on connection failure
        print(
            f"\n{YELLOW}Cannot connect to Ollama at {OLLAMA_HOST}.\n"
            f"Make sure Ollama is running ('ollama serve' or start the Ollama desktop app).{RESET}"
        )
    except Exception as e:
        messages.pop()
        print(f"\n{YELLOW}Unexpected error: {e}{RESET}")

def main():
    # Enable ANSI escape sequences on Windows if needed
    if os.name == "nt":
        os.system("")

    print("=" * 50)
    print(f"{BOLD}LEO - Your Personal AI{RESET}")
    print(f"Model: {GREEN}{MODEL}{RESET}")
    print(f"Type {CYAN}/help{RESET} for commands or {CYAN}/exit{RESET} to quit.")
    print("=" * 50)

    while True:
        try:
            prompt_label = f"{BOLD}You:{RESET} "
            question = input(f"\n{prompt_label}").strip()
        except (EOFError, KeyboardInterrupt):
            print(f"\n{CYAN}LEO:{RESET} Goodbye!")
            break

        if not question:
            continue

        cmd = question.lower()
        if cmd in ("/exit", "/quit"):
            print(f"{CYAN}LEO:{RESET} Goodbye!")
            break

        if cmd == "/help":
            print_help()
            continue

        if cmd == "/reset":
            messages.clear()
            messages.append({"role": "system", "content": SYSTEM_PROMPT})
            print(f"{CYAN}LEO:{RESET} Conversation context cleared.")
            continue

        if cmd == "/history":
            user_turns = sum(1 for m in messages if m["role"] == "user")
            print(f"{DIM}Context has {len(messages)} total messages ({user_turns} user turns).{RESET}")
            continue

        if cmd == "/model":
            print(f"{DIM}Active Model: {MODEL} | Endpoint: {OLLAMA_URL}{RESET}")
            continue

        ask_leo_stream(question)

if __name__ == "__main__":
    main()
