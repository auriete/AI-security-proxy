import json
import re
import base64
import socket
import threading
from mitmproxy import http

TARGET_DOMAINS = ["chatgpt.com", "openai.com"]
FORBIDDEN_KEYWORDS = ["CompanyName", "confidential", "password123", "internal_db"]

BLOCKED_DOMAINS = [
    "gemini.google.com", 
    "aistudio.google.com",
    "perplexity.ai", 
    "claude.ai", 
    "copilot.microsoft.com",
    "copilot.cloud.microsoft",
    "copilot.com"
]

client_socket = None
lock = threading.Lock()

def start_socket_server():
    global client_socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(("0.0.0.0", 9091))
    server_socket.listen(5)
    print("\n[+] Socket server active on port 9091. Waiting for connection...")

    while True:
        try:
            conn, addr = server_socket.accept()
            global address
            address = addr
            with lock:
                client_socket = conn
            print(f"\n[+] Admin client connected from {addr}")
        except Exception as e:
            print(f"Server error: {e}")
            break

server_thread = threading.Thread(target=start_socket_server, daemon=True)
server_thread.start()

def send_data(data: str):
    global client_socket
    with lock:
        if client_socket is not None:
            try:
                payload = data + "<END_OF_MSG>"
                client_socket.sendall(payload.encode("utf-8"))
            except (socket.error, BrokenPipeError, ConnectionResetError):
                print("\n[-] Admin client disconnected.")
                client_socket = None

def extract_user_identity(flow: http.HTTPFlow) -> dict:
    identity = {"name": "Unknown / Guest", "email": "Unknown"}
    auth_header = flow.request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header.split(" ")[1]
        try:
            parts = token.split(".")
            if len(parts) >= 2:
                payload_b64 = parts[1] + "=" * (-len(parts[1]) % 4)
                decoded_bytes = base64.urlsafe_b64decode(payload_b64)
                payload = json.loads(decoded_bytes.decode("utf-8", errors="ignore"))
                if "email" in payload:
                    identity["email"] = payload["email"]
                profile = payload.get("https://api.openai.com/profile", {})
                if isinstance(profile, dict):
                    identity["name"] = profile.get("name", identity["name"])
                    identity["email"] = profile.get("email", identity["email"])
        except Exception:
            pass

    if identity["email"] == "Unknown":
        cookie_header = flow.request.headers.get("Cookie", "")
        email_match = re.search(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', cookie_header)
        if email_match:
            identity["email"] = email_match.group(0)

    return identity

def parse_chatgpt_payload(payload: dict) -> str | None:
    try:
        messages = payload.get("messages", [])
        for msg in messages:
            author = msg.get("author", {})
            role = author.get("role") if isinstance(author, dict) else msg.get("role")
            if role == "user":
                content = msg.get("content", {})
                if isinstance(content, dict):
                    parts = content.get("parts", [])
                    text_parts = [str(p) for p in parts if isinstance(p, (str, int, float))]
                    if text_parts:
                        return " ".join(text_parts)
                elif isinstance(content, str):
                    return content
    except Exception:
        pass
    return None

def contains_forbidden_text(prompt: str) -> str | None:
    prompt_lower = prompt.lower()
    for kw in FORBIDDEN_KEYWORDS:
        if kw.lower() in prompt_lower:
            return kw
    return None

def request(flow: http.HTTPFlow) -> None:
    host = flow.request.pretty_host

    # --- FIX 1: BLOCK FORBIDDEN DOMAINS IMMEDIATELY ---
    if any(site in host for site in BLOCKED_DOMAINS):
        user_info = extract_user_identity(flow)

        alert_msg = (
            "\n" + "!" * 60 + "\n"
            + f"[SITE BLOCKED] Blocked connection to forbidden AI service: {host}\n"
            + f"IP logged: {address}\n"
            + "!" * 60 + "\n"
        )
        
        # Kill the request directly from proxy
        flow.response = http.Response.make(
            403,
            b"Access Denied: This AI site is blocked by enterprise security policy.",
            {"Content-Type": "text/plain"}
        )

        print(alert_msg, flush=True)
        send_data(alert_msg)
        return  # CRITICAL: Stop execution so it doesn't run the rest of the method

    # --- standard checks for inspectable traffic ---
    if flow.request.method not in ["POST", "PUT"]:
        return

    path = flow.request.path
    if any(ignore in path for ignore in ["/sentinel/", "/lat/", "/telemetry", "/ces/", "/prepare"]):
        return

    raw_body = flow.request.get_text()
    if not raw_body or raw_body.strip() == "next" or raw_body.startswith("gAAAAA"):
        return

    prompt_text = None
    try:
        payload = json.loads(raw_body)
        prompt_text = parse_chatgpt_payload(payload)
    except Exception:
        pass

    if not prompt_text:
        parts_match = re.search(r'"parts"\s*:\s*\[\s*"([^"]+)"\s*\]', raw_body)
        if parts_match:
            prompt_text = parts_match.group(1)

    if prompt_text and prompt_text.strip() not in ["next", ""]:
        try:
            prompt_text = prompt_text.encode().decode('unicode_escape')
        except Exception:
            pass

        cleaned_prompt = prompt_text.strip()
        blocked_kw = contains_forbidden_text(cleaned_prompt)

        if blocked_kw:
            user_info = extract_user_identity(flow)
            
            alert_msg = (
                "\n" + "!" * 60 + "\n"
                + "[PROMPT BLOCKED BY POLICY]\n"
                + f"User Email    : {user_info['email']}\n"
                + f"Target        : {host}\n"
                + f"Matched Keyword: '{blocked_kw}'\n"
                + "-" * 60 + "\n"
                + cleaned_prompt + "\n"
                + "!" * 60 + "\n"
            )
            print(alert_msg, flush=True)
            send_data(alert_msg)

            flow.response = http.Response.make(
                403,
                json.dumps({
                    "error": {
                        "message": f"Request blocked: Prompt contains restricted keyword '{blocked_kw}'.",
                        "type": "policy_violation_error",
                        "code": "forbidden_content"
                    }
                }),
                {"Content-Type": "application/json"}
            )
            return

        user_info = extract_user_identity(flow)
        result = (
            "\n" + "=" * 60 + "\n"
            + "[Normal user prompt]\n"
            + f"User Email: {user_info['email']}\n"
            + f"Target    : {host}\n"
            + "-" * 60 + "\n"
            + prompt_text.strip() + "\n"
            + "=" * 60 + "\n"
        )
        print(result)
        send_data(result)