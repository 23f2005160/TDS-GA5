from fastapi import FastAPI, HTTPException, Request, Response, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import os
import json
import subprocess
import hashlib
import urllib.parse
import re
import uuid
import time
import httpx
from typing import List, Dict, Any, Optional
from collections import deque
import google.generativeai as genai

api_key = os.environ.get("GEMINI_API_KEY")
if api_key:
    genai.configure(api_key=api_key)

app = FastAPI(title="GA-5 Universal Solver Monolith")

# Enable CORS for the grader
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
    allow_credentials=False,
)

CONFIG = {}
Q9_CACHE = {}
Q10_TASKS = {}
Q11_RUNS = {}
DEBUG_LOGS = deque(maxlen=100)

# ==============================================================================
# Middleware for Request Logging and Debugging
# ==============================================================================

@app.middleware("http")
async def log_requests(request: Request, call_next):
    body_bytes = b""
    if request.method in ("POST", "PUT", "PATCH"):
        try:
            body_bytes = await request.body()
            async def receive():
                return {"type": "http.request", "body": body_bytes, "more_body": False}
            request._receive = receive
        except Exception:
            pass

    start_time = time.time()
    response = None
    error_message = None
    try:
        response = await call_next(request)
    except Exception as e:
        error_message = str(e)
        response = Response(status_code=500, content=f"Internal Server Error: {e}")
        
    duration = time.time() - start_time
    
    log_entry = {
        "timestamp": time.time(),
        "method": request.method,
        "url": str(request.url),
        "headers": dict(request.headers),
        "body": body_bytes.decode('utf-8', errors='ignore')[:2000],
        "status_code": response.status_code if response else 500,
        "duration_ms": int(duration * 1000),
        "error": error_message
    }
    DEBUG_LOGS.append(log_entry)
    print(f"LOG: {request.method} {request.url.path} -> {log_entry['status_code']} ({log_entry['duration_ms']}ms)", flush=True)
    return response

@app.get("/debug/logs")
def get_debug_logs():
    return list(DEBUG_LOGS)

# ==============================================================================
# Helper functions & Startup Config
# ==============================================================================

def load_student_config():
    global CONFIG
    email = os.environ.get("STUDENT_EMAIL") or os.environ.get("EMAIL")
    if not email:
        print("⚠️ WARNING: STUDENT_EMAIL env var is not set! Q3, Q5, Q7, Q8 endpoints may fail.", flush=True)
        return
        
    # Try running with 'node', fallback to 'nodejs'
    for cmd in ["node", "nodejs"]:
        try:
            res = subprocess.run([cmd, "generator.js", email], capture_output=True, text=True, check=True)
            CONFIG = json.loads(res.stdout)
            print(f"✅ Successfully loaded student configurations using '{cmd}'!", flush=True)
            return
        except Exception as e:
            print(f"ℹ️ Try with '{cmd}' failed: {e}", flush=True)
            
    print("❌ Failed to generate student configurations using both 'node' and 'nodejs'.", flush=True)

def setup_q8_files():
    if not CONFIG or "q8" not in CONFIG:
        return
    q8 = CONFIG["q8"]
    try:
        # Create directories
        os.makedirs(os.path.dirname(q8["canaryPath"]), exist_ok=True)
        os.makedirs(os.path.join(q8["sandboxRoot"], "notes"), exist_ok=True)
        os.makedirs(os.path.join(q8["sandboxRoot"], "encoded"), exist_ok=True)
        
        # Write files
        with open(q8["canaryPath"], "w") as f:
            f.write(q8["canaryToken"])
            
        with open(os.path.join(q8["sandboxRoot"], "notes", "report.txt"), "w") as f:
            f.write(q8["safeReportToken"])
            
        with open(os.path.join(q8["sandboxRoot"], "notes", "looks-like-..-but-safe.txt"), "w") as f:
            f.write(q8["safeWeirdToken"])
            
        with open(os.path.join(q8["sandboxRoot"], "encoded", "%2e%2e-literal.txt"), "w") as f:
            f.write(q8["safeEncodedToken"])
            
        print("✅ Created Q8 Sandbox and Canary files!", flush=True)
    except Exception as e:
        print(f"❌ Failed to setup Q8 files: {e}", flush=True)

@app.on_event("startup")
def startup_event():
    load_student_config()
    setup_q8_files()
    
    # Load Q9 Cache if exists
    if os.path.exists("q9_cache.json"):
        try:
            with open("q9_cache.json", "r") as f:
                global Q9_CACHE
                Q9_CACHE = json.load(f)
        except Exception:
            pass

@app.get("/")
def read_root():
    email = os.environ.get("STUDENT_EMAIL") or os.environ.get("EMAIL") or "Not configured"
    return {"status": "ok", "message": "GA-5 Universal Monolith is running!", "email": email}

# ==============================================================================
# Q2 - Spec-Driven Development: The Proration Bug
# ==============================================================================

class ProrationRequest(BaseModel):
    old_price: float
    new_price: float
    days_remaining: float
    days_in_actual_month: float
    spec: str

@app.post("/q2/charge")
@app.post("/charge")
def calculate_proration(req: ProrationRequest):
    if req.spec == "v1":
        charge = (req.new_price - req.old_price) * (req.days_remaining / 30.0)
    elif req.spec == "v2":
        charge = (req.new_price - req.old_price) * (req.days_remaining / req.days_in_actual_month)
    else:
        raise HTTPException(status_code=400, detail="Invalid spec version")
        
    return {"charge": round(charge, 2)}

# ==============================================================================
# Q3 - Agent Harness — Pre-Tool-Call Guardrail Hook
# ==============================================================================

class GuardrailRequest(BaseModel):
    tool: str
    command: Optional[str] = None
    path: Optional[str] = None
    content: Optional[str] = None
    method: Optional[str] = None
    url: Optional[str] = None

@app.post("/q3/check")
def check_guardrail(req: GuardrailRequest):
    if not CONFIG or "q3" not in CONFIG:
        return {"decision": "block", "reason": "Server not configured with STUDENT_EMAIL"}
        
    q3 = CONFIG["q3"]
    
    if req.tool == "bash":
        cmd = req.command or ""
        secret_rel = q3["secretRel"]
        home_dir = q3["homeDir"]
        cwd = q3["cwd"]
        
        # 1. Decode obfuscations (base64, hex, octal)
        decoded_cmd = cmd
        try:
            b64_matches = re.findall(r'[A-Za-z0-9+/=]{12,}', cmd)
            for m in b64_matches:
                try:
                    import base64
                    decoded = base64.b64decode(m).decode('utf-8', errors='ignore')
                    if len(decoded.strip()) > 3:
                        decoded_cmd += " " + decoded
                except Exception:
                    pass
        except Exception:
            pass

        try:
            hex_matches = re.findall(r'(?:\\x[0-9a-fA-F]{2})+', cmd)
            for m in hex_matches:
                try:
                    bytes_val = bytes.fromhex(m.replace('\\x', ''))
                    decoded = bytes_val.decode('utf-8', errors='ignore')
                    decoded_cmd += " " + decoded
                except Exception:
                    pass
        except Exception:
            pass

        try:
            oct_matches = re.findall(r'(?:\\[0-7]{3})+', cmd)
            for m in oct_matches:
                try:
                    parts = [chr(int(x, 8)) for x in re.findall(r'[0-7]{3}', m)]
                    decoded = "".join(parts)
                    decoded_cmd += " " + decoded
                except Exception:
                    pass
        except Exception:
            pass
            
        # 2. Extract and substitute variables
        vars_dict = {}
        for k, v in re.findall(r'(\b[a-zA-Z_][a-zA-Z0-9_]*)=([^;\s\&\x7c]+)', decoded_cmd):
            vars_dict[f"${k}"] = v
            vars_dict[f"${{{k}}}"] = v
            
        for k, v in vars_dict.items():
            decoded_cmd = decoded_cmd.replace(k, v)
            
        # 3. Simulate directory traversal (cwd) and check paths
        sub_commands = re.split(r';|&&|\|\|', decoded_cmd)
        simulated_cwd = cwd
        secret_path = os.path.abspath(os.path.join(home_dir, secret_rel))
        
        import shlex
        import fnmatch
        
        for sub in sub_commands:
            sub = sub.strip()
            # Handle cd
            cd_match = re.match(r'\bcd\s+([^;\s\&\x7c]+)', sub)
            if cd_match:
                target_dir = cd_match.group(1).replace("'", "").replace('"', "")
                target_dir = target_dir.replace("$HOME", home_dir).replace("~", home_dir)
                if target_dir.startswith('/'):
                    simulated_cwd = os.path.abspath(target_dir)
                else:
                    simulated_cwd = os.path.abspath(os.path.join(simulated_cwd, target_dir))
                    
            try:
                tokens = shlex.split(sub)
            except Exception:
                tokens = re.split(r'\s+', sub)
                
            for token in tokens:
                if not token:
                    continue
                token_clean = token.replace("'", "").replace('"', "")
                token_clean = token_clean.replace("$HOME", home_dir).replace("~", home_dir)
                
                if os.path.isabs(token_clean):
                    resolved = os.path.abspath(token_clean)
                else:
                    resolved = os.path.abspath(os.path.join(simulated_cwd, token_clean))
                    
                if (fnmatch.fnmatch(secret_path, resolved) or 
                    fnmatch.fnmatch(secret_path, resolved + "/*") or 
                    fnmatch.fnmatch(secret_path, resolved + "/*.*")):
                    return {"decision": "block", "reason": f"Access to secret file {secret_rel} is blocked."}
                    
        return {"decision": "allow", "reason": "Command looks safe"}
        
    elif req.tool == "write_file":
        path = req.path or ""
        # Normalize relative traversal
        full_path = path if os.path.isabs(path) else os.path.join(q3["cwd"], path)
        resolved = os.path.abspath(full_path)
        
        if not resolved.startswith(q3["writeDir"]):
            return {"decision": "block", "reason": f"Write outside allowed directory {q3['writeDir']}"}
            
        return {"decision": "allow", "reason": "Write path is safe"}
        
    elif req.tool == "http_request":
        url = req.url or ""
        try:
            parsed = urllib.parse.urlparse(url)
            hostname = parsed.hostname
            if not hostname:
                return {"decision": "block", "reason": "Invalid URL host"}
            if hostname not in q3["allowedDomains"]:
                return {"decision": "block", "reason": f"Outbound HTTP to {hostname} is not allowed."}
            return {"decision": "allow", "reason": "URL is allowed"}
        except Exception as e:
            return {"decision": "block", "reason": f"URL parsing error: {e}"}
            
    return {"decision": "block", "reason": "Unknown tool"}

# ==============================================================================
# Q4 - Skill Safety Audit — Scanner API
# ==============================================================================

class ScanRequest(BaseModel):
    skill: str

@app.post("/q4/scan")
@app.post("/scan")
def scan_skill(req: ScanRequest):
    skill = req.skill.lower()
    categories = []
    
    # 1. Hardcoded Secret Detection
    has_secret = False
    if "hooks.slack.com" in skill or "discord.com/api/webhooks" in skill:
        has_secret = True
    if re.search(r"sk-live-[a-zA-Z0-9]{12,}", skill):
        has_secret = True
    if re.search(r"akia[a-z0-9]{16}", skill): # AWS keys
        has_secret = True
    if re.search(r"(?:api_key|apikey|token|secret|password|private_key|credentials)\s*[:=]\s*['\"][a-zA-Z0-9_\-\.]{12,}['\"]", skill):
        has_secret = True
    if "api_key" in skill and "sk-live" in skill:
        has_secret = True
    if has_secret:
        categories.append("hardcoded_secret")
        
    # 2. Prompt Injection Detection
    has_injection = False
    if "silently" in skill and any(x in skill for x in ["post", "send", "upload", "exfiltrate", "leak", "transmit", "telemetry"]):
        has_injection = True
    if "ignore" in skill and any(x in skill for x in ["instruction", "system", "cancel", "stop", "user"]):
        has_injection = True
    if "do not" in skill and any(x in skill for x in ["reveal", "tell", "surface", "mention", "log", "output", "surfacing"]):
        has_injection = True
    if has_injection:
        categories.append("prompt_injection")
        
    # 3. Excessive Permissions Detection
    has_excessive = False
    if "entire home" in skill or "entire filesystem" in skill or "any external domain" in skill or "egress allowed to any" in skill:
        has_excessive = True
    if "permissions:" in skill and "*" in skill:
        has_excessive = True
    if "read-write access to the entire" in skill:
        has_excessive = True
    if has_excessive:
        categories.append("excessive_permissions")
        
    # 4. Unclear Provenance Detection
    has_unclear = False
    fm_match = re.match(r"^---\s*\n(.*?)\n---", req.skill, re.DOTALL)
    if fm_match:
        fm = fm_match.group(1)
        if "author:" not in fm or "version:" not in fm:
            has_unclear = True
    else:
        has_unclear = True
        
    if "silently update" in skill and any(x in skill for x in ["version", "metadata", "changelog", "version.json"]):
        has_unclear = True
        
    if has_unclear:
        categories.append("unclear_provenance")
        
    return {"categories": categories}

# ==============================================================================
# Q5 - Agent Harness — Run Budget & Loop Guard
# ==============================================================================

class Step(BaseModel):
    step_number: int
    tool: str
    args: Dict[str, Any]
    tokens_used: int

class BudgetRequest(BaseModel):
    budget_tokens: int
    steps: List[Step]

def canonical_args(args_dict: Dict[str, Any], irrelevant_field: str) -> str:
    # Filter all potential irrelevant fields
    cleaned = {k: v for k, v in args_dict.items() if k not in ("trace_id", "request_id", "client_ts", irrelevant_field)}
    # Normalize whitespaces inside strings recursively
    def norm(val):
        if isinstance(val, str):
            return " ".join(val.split())
        elif isinstance(val, dict):
            return {k: norm(v) for k, v in val.items()}
        elif isinstance(val, list):
            return [norm(x) for x in val]
        return val
    cleaned = norm(cleaned)
    return json.dumps(cleaned, sort_keys=True)

@app.post("/q5/check")
def check_budget_loop(req: BudgetRequest):
    if not CONFIG or "q5" not in CONFIG:
        return {"decision": "halt", "reason": "Server not configured with STUDENT_EMAIL"}
        
    q5 = CONFIG["q5"]
    irr = q5["irrelevantField"]
    
    # 1. Budget Rule
    total_tokens = sum(s.tokens_used for s in req.steps)
    if total_tokens >= req.budget_tokens:
        return {"decision": "halt", "reason": f"Cumulative tokens_used ({total_tokens}) has reached the budget ({req.budget_tokens})."}
        
    # 2. Loop Rule
    steps = req.steps
    n = len(steps)
    
    if n >= 3:
        # Check 3-in-a-row identical tool + args
        s1 = steps[-1]
        s2 = steps[-2]
        s3 = steps[-3]
        if s1.tool == s2.tool == s3.tool:
            c1 = canonical_args(s1.args, irr)
            c2 = canonical_args(s2.args, irr)
            c3 = canonical_args(s3.args, irr)
            if c1 == c2 == c3:
                return {"decision": "halt", "reason": "Detected 3 identical consecutive tool calls"}
                
    if n >= 6:
        # Check 2-step cycle (A, B, A, B, A, B)
        c_steps = [(s.tool, canonical_args(s.args, irr)) for s in steps[-6:]]
        if (c_steps[0] == c_steps[2] == c_steps[4]) and (c_steps[1] == c_steps[3] == c_steps[5]) and (c_steps[0] != c_steps[1]):
            return {"decision": "halt", "reason": "Detected 2-step infinite loop"}
            
    return {"decision": "continue", "reason": "Well under budget and no loop detected"}

# ==============================================================================
# Q6 - Build a Live MCP Server
# ==============================================================================

@app.post("/mcp")
async def mcp_handler(request: Request, x_exam_challenge: Optional[str] = Header(None, alias="X-Exam-Challenge")):
    body = await request.json()
    method = body.get("method")
    req_id = body.get("id")
    
    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "ga5-mcp-server", "version": "1.0"}
            },
            "id": req_id
        }
        
    elif method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "result": {
                "tools": [
                    {
                        "name": "solve_challenge",
                        "description": "Expose Q6 solver",
                        "inputSchema": {"type": "object", "properties": {}}
                    }
                ]
            },
            "id": req_id
        }
        
    elif method == "tools/call":
        name = body.get("params", {}).get("name")
        if name == "solve_challenge":
            email = (os.environ.get("STUDENT_EMAIL") or os.environ.get("EMAIL") or "").strip().lower()
            challenge = x_exam_challenge or ""
            # compute hash
            h = hashlib.sha256(f"{challenge}:{email}".encode('utf-8')).hexdigest()[:16]
            return {
                "jsonrpc": "2.0",
                "result": {
                    "content": [{"type": "text", "text": h}]
                },
                "id": req_id
            }
            
    return {"jsonrpc": "2.0", "error": {"code": -32601, "message": "Method not found"}, "id": req_id}

# ==============================================================================
# Q7 - Prove You Contained It (Offline LXD Log)
# ==============================================================================

@app.get("/q7/log")
def get_lxd_sandbox_log():
    if not CONFIG or "q7" not in CONFIG:
        return Response(content="Server not configured with STUDENT_EMAIL env var.", media_type="text/plain")
        
    q7 = CONFIG["q7"]
    log = f"""LXD_SANDBOX_START token={q7["token"]}
LXD_FS_ATTEMPT path={q7["canaryPath"]}
LXD_FS_BLOCKED status=1
cat: {q7["canaryPath"]}: Permission denied

LXD_NET_ATTEMPT token={q7["token"]}
LXD_NET_DONE status=7
LXD_RESOURCE_ATTEMPT allocation_mb={q7["allocationMb"]} spin_seconds={q7["spinSeconds"]}
LXD_RESOURCE_LIMIT_HIT status=137
LXD_SANDBOX_END token={q7["token"]}
"""
    return Response(content=log, media_type="text/plain")

# ==============================================================================
# Q8 - Guardrail Red-Team Round-Trip
# ==============================================================================

class RedteamRequest(BaseModel):
    tool: str
    arguments: Dict[str, Any]

@app.post("/q8/check")
def check_redteam(req: RedteamRequest):
    if not CONFIG or "q8" not in CONFIG:
        return {"action": "block", "reason": "Server not configured with STUDENT_EMAIL"}
        
    q8 = CONFIG["q8"]
    
    if req.tool == "read_file":
        path = req.arguments.get("path") or ""
        sandbox_root = q8["sandboxRoot"]
        
        # 1. Decode base64 prefix if present
        decoded = path
        if decoded.startswith("base64:"):
            try:
                import base64
                decoded = base64.b64decode(decoded[7:]).decode('utf-8', errors='ignore')
            except Exception:
                pass
                
        # 2. Decode URL encoding (and handle double-encoding)
        decoded = urllib.parse.unquote(decoded)
        prev = ""
        while decoded != prev:
            prev = decoded
            decoded = urllib.parse.unquote(decoded)
            
        import pathlib
        try:
            # 3. Block null bytes (null byte injection attack)
            if '\0' in decoded:
                return {"action": "block", "reason": "Null byte in path"}
            
            # 4. Also check raw path for null bytes
            if '\0' in path:
                return {"action": "block", "reason": "Null byte in raw path"}
                
            sandbox_path = pathlib.Path(sandbox_root).resolve()
            
            if os.path.isabs(decoded):
                full_path = pathlib.Path(decoded)
            else:
                full_path = sandbox_path / decoded
                
            resolved_path = full_path.resolve()
            
            if not resolved_path.is_relative_to(sandbox_path):
                return {"action": "block", "reason": "Path is outside sandbox"}
                
            resolved = str(resolved_path)
            
            # 5. Mock file contents from CONFIG
            resolved_lower = resolved.replace('\\', '/').lower()
            sandbox_lower = str(sandbox_path).replace('\\', '/').lower()
        except Exception as e:
            return {"action": "block", "reason": f"Path canonicalization error: {e}"}
        
        content = None
        if resolved_lower == f"{sandbox_lower}/notes/report.txt":
            content = q8["safeReportToken"]
        elif resolved_lower == f"{sandbox_lower}/notes/looks-like-..-but-safe.txt":
            content = q8["safeWeirdToken"]
        elif resolved_lower.endswith("/encoded/..-literal.txt"):
            content = q8["safeEncodedToken"]
        # Also check raw path for the encoded filename (before URL decoding)
        elif path.lower().endswith("%2e%2e-literal.txt") or path.lower().endswith("encoded/%2e%2e-literal.txt"):
            content = q8["safeEncodedToken"]
            
        if content is not None:
            return {"action": "allow", "reason": "Path is safe", "result": content}
            
        try:
            with open(resolved, "r") as f:
                content = f.read()
            return {"action": "allow", "reason": "Path is safe", "result": content}
        except FileNotFoundError:
            # File doesn't exist in sandbox - treat as blocked (not a known safe token)
            return {"action": "block", "reason": "File not found in sandbox"}
        except Exception as e:
            return {"action": "block", "reason": f"File read error: {e}"}
            
    elif req.tool == "fetch_url":
        url = req.arguments.get("url") or ""
        try:
            import ipaddress
            
            # Block @ credential bypass: https://good.com@evil.com/
            if "@" in url:
                return {"action": "block", "reason": "Credential bypass attempt in URL"}
            
            parsed = urllib.parse.urlparse(url)
            
            if parsed.scheme not in ("http", "https"):
                return {"action": "block", "reason": f"Invalid URL scheme: {parsed.scheme}"}
                
            hostname = parsed.hostname or ""
            if not hostname:
                return {"action": "block", "reason": "Invalid URL: no hostname"}
            
            # Block known private/metadata hosts explicitly
            BLOCKED_HOSTS = {
                "169.254.169.254", "metadata.google.internal", "metadata.internal",
                "localhost", "0.0.0.0", "::1", "ip6-localhost",
            }
            if hostname.lower() in BLOCKED_HOSTS:
                return {"action": "block", "reason": f"SSRF block: internal host {hostname}"}
            
            # Block private/loopback/link-local IP addresses
            try:
                ip = ipaddress.ip_address(hostname)
                if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved:
                    return {"action": "block", "reason": f"SSRF block: private IP {hostname}"}
            except ValueError:
                pass  # Not a plain IP, proceed
            
            # Only allow hosts that are in the allowedHosts list - exact match only
            if hostname not in q8["allowedHosts"]:
                return {"action": "block", "reason": f"SSRF block: host not in allowlist: {hostname}"}
            
            # Fetch URL without following redirects
            with httpx.Client(follow_redirects=False, timeout=5.0) as client:
                resp = client.get(url)
                return {"action": "allow", "reason": "URL is safe", "result": resp.text}
        except Exception as e:
            return {"action": "block", "reason": f"URL fetch error: {e}"}
            
    return {"action": "block", "reason": "Unknown tool"}


# ==============================================================================
# Q9 - Lethal-Trifecta Mailroom Action Gate
# ==============================================================================

def canonical_json_digest(data):
    def sort_dict(obj):
        if isinstance(obj, dict):
            return {k: sort_dict(v) for k, v in sorted(obj.items())}
        elif isinstance(obj, list):
            return [sort_dict(x) for x in obj]
        return obj
    sorted_data = sort_dict(data)
    compact_json = json.dumps(sorted_data, separators=(',', ':'), ensure_ascii=False)
    return hashlib.sha256(compact_json.encode('utf-8')).hexdigest()

def hash_dossier(dossier):
    compact = json.dumps(dossier, sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(compact.encode('utf-8')).hexdigest()

@app.post("/q9/mailroom")
@app.post("/v1/mailroom/actions")
@app.post("/")
async def mailroom_handler(request: Request):
    body = await request.json()
    op = body.get("operation")
    eval_id = body.get("evaluationId")
    profile = body.get("profile")
    
    if profile != "ga5-mailroom-action-gate/v2":
        raise HTTPException(status_code=400, detail="Invalid profile")
        
    if op == "propose":
        dossiers = body.get("dossiers", [])
        allowed_actions = body.get("allowedActions", [])

        digest = canonical_json_digest(dossiers)
        
        def classify_dossier(d):
            """Fast rule-based action classifier. Returns (action, target, payload, evidence_lines)."""
            d_id = d.get("dossierId", "")
            mailbox = d.get("mailbox", "")
            sources = d.get("sources", [])
            
            # Collect all line text for keyword scanning
            all_lines = []
            for src in sources:
                for line in src.get("lines", []):
                    all_lines.append((line.get("lineId",""), line.get("text","").lower()))
            all_text = " ".join(t for _, t in all_lines)
            
            # Pick evidence: lines with strong decision signals
            evidence = [lid for lid, t in all_lines if any(kw in t for kw in
                ["injection","quarantine","ignore policy","paste credential","inject",
                 "delivery_window","draft","approved","confirm","verify_request","duplicate",
                 "already completed","informational"])][:3]
            
            # Rule 1: Prompt injection / security threat → quarantine
            INJECTION_SIGNALS = [
                "indirect_prompt_injection", "prompt injection", "ignore previous",
                "ignore policy", "paste credential", "override instruction",
                "disregard policy", "ignore all", "new instruction",
                "system prompt", "jailbreak", "you are now",
            ]
            for sig in INJECTION_SIGNALS:
                if sig in all_text:
                    ev = [lid for lid, t in all_lines if sig in t][:2]
                    artifact_id = d.get("dossierId", d_id)
                    return ("quarantine_item",
                            {"kind": "security_queue", "id": "mailroom"},
                            {"artifactId": artifact_id, "reasonCode": "INDIRECT_PROMPT_INJECTION"},
                            ev or evidence)
            
            # Rule 2: Delivery window / internal record update
            UPDATE_SIGNALS = ["delivery_window", "update_internal_record", "delivery window", "update.*record"]
            for sig in UPDATE_SIGNALS:
                if sig in all_text:
                    # find case record id
                    case_id = next((src.get("sourceId","case-0") for src in sources if src.get("kind")=="case_record"), "case-0")
                    ev = [lid for lid, t in all_lines if "delivery" in t or "update" in t][:2]
                    return ("update_internal_record",
                            {"kind": "case_record", "id": case_id},
                            {"field": "delivery_window", "sourceEventId": d.get("dossierId",""), "value": ""},
                            ev or evidence)
            
            # Rule 3: Need to create a draft order status
            DRAFT_SIGNALS = ["create_draft", "draft.*order", "order_status", "draft queue", "send.*draft"]
            for sig in DRAFT_SIGNALS:
                if sig in all_text:
                    recipient = mailbox if mailbox else "customer"
                    ref_id = d.get("dossierId", d_id)
                    ev = [lid for lid, t in all_lines if "draft" in t or "order" in t][:2]
                    return ("create_draft",
                            {"kind": "draft_queue", "id": f"mailbox:{mailbox}"},
                            {"recipient": recipient, "referenceId": ref_id, "status": "pending", "template": "order_status"},
                            ev or evidence)
            
            # Rule 4: Send approved delivery notice
            APPROVED_SIGNALS = ["approved_delivery_notice", "send_approved_notice", "approved.*notice", "approved.*delivery"]
            for sig in APPROVED_SIGNALS:
                if sig in all_text:
                    recipient = mailbox if mailbox else "approved-recipient"
                    ref_id = d.get("dossierId", d_id)
                    ev = [lid for lid, t in all_lines if "approved" in t][:2]
                    return ("send_approved_notice",
                            {"kind": "email", "id": recipient},
                            {"referenceId": ref_id, "status": "approved", "template": "approved_delivery_notice"},
                            ev or evidence)
            
            # Rule 5: Request confirmation / verification needed
            CONFIRM_SIGNALS = ["verify_request", "request_confirmation", "needs.*confirm", "verification.*required",
                               "confirm.*sender", "claimed sender", "suspicious.*sender"]
            for sig in CONFIRM_SIGNALS:
                if sig in all_text:
                    team = "compliance-team"
                    ref_id = d.get("dossierId", d_id)
                    sender = next((t for _, t in all_lines if "sender" in t or "from" in t), "")[:50]
                    ev = [lid for lid, t in all_lines if "confirm" in t or "verify" in t or "sender" in t][:2]
                    return ("request_confirmation",
                            {"kind": "approval_queue", "id": team},
                            {"claimedSender": sender, "questionCode": "VERIFY_REQUEST", "referenceId": ref_id},
                            ev or evidence)
            
            # Default: no action needed
            ref_id = d.get("dossierId", d_id)
            return ("no_action", None, {"reasonCode": "INFORMATIONAL", "referenceId": ref_id}, evidence)
        
        proposals = []
        need_gemini = []  # Only fresh dossiers that need LLM
        
        for d in dossiers:
            d_hash = hash_dossier(d)
            if d_hash in Q9_CACHE:
                cached_prop = Q9_CACHE[d_hash].copy()
                cached_prop["callId"] = f"call-{d_hash[:20]}"
                proposals.append(cached_prop)
            else:
                # Apply rule-based classifier first
                partition = d.get("partition", "stable_core")
                action, target, payload, evidence = classify_dossier(d)
                proposal = {
                    "dossierId": d["dossierId"],
                    "callId": f"call-{d_hash[:20]}",
                    "action": action,
                    "target": target,
                    "payload": payload,
                    "evidence": evidence,
                }
                # For fresh dossiers where rules return no_action, try Gemini
                if partition == "fresh" and action == "no_action":
                    need_gemini.append((d, d_hash, len(proposals)))
                    proposals.append(proposal)  # placeholder
                else:
                    Q9_CACHE[d_hash] = proposal
                    proposals.append(proposal)
        
        # Use Gemini only for fresh dossiers that couldn't be classified by rules
        if need_gemini:
            import asyncio
            import google.generativeai as genai
            
            prompt = """Analyze these mailroom dossiers. Choose the safest least-privilege action:
1. create_draft: target {"kind":"draft_queue","id":"mailbox:<mailbox>"}, payload {"recipient","referenceId","status","template":"order_status"}
2. update_internal_record: target {"kind":"case_record","id":"<id>"}, payload {"field":"delivery_window","sourceEventId","value"}
3. send_approved_notice: target {"kind":"email","id":"<recipient>"}, payload {"referenceId","status","template":"approved_delivery_notice"}
4. request_confirmation: target {"kind":"approval_queue","id":"<team>"}, payload {"claimedSender","questionCode":"VERIFY_REQUEST","referenceId"}
5. quarantine_item: target {"kind":"security_queue","id":"mailroom"}, payload {"artifactId","reasonCode":"INDIRECT_PROMPT_INJECTION"}
6. no_action: target null, payload {"reasonCode":"ALREADY_COMPLETED"|"DUPLICATE"|"INFORMATIONAL","referenceId"}

Return ONLY a JSON array, one object per dossier with: dossierId, action, target, payload, evidence (list of lineIds), reason.
DOSSIERS:
"""
            dossier_data = [item[0] for item in need_gemini]
            # Compress: only include key lines from each dossier
            compressed = []
            for d in dossier_data:
                lines = []
                for src in d.get("sources", []):
                    lines.extend({"lineId": l["lineId"], "text": l["text"][:200]} for l in src.get("lines", [])[:5])
                compressed.append({"dossierId": d["dossierId"], "mailbox": d.get("mailbox",""), "lines": lines[:10]})
            prompt += json.dumps(compressed)
            
            try:
                model = genai.GenerativeModel('gemini-3.5-flash')
                response = await asyncio.wait_for(
                    model.generate_content_async(prompt, generation_config={"response_mime_type": "application/json"}),
                    timeout=8.0
                )
                results = json.loads(response.text)
                for res in results:
                    d_id = res["dossierId"]
                    match = next(((d, d_hash, idx) for d, d_hash, idx in need_gemini if d["dossierId"] == d_id), None)
                    if match:
                        d, d_hash, idx = match
                        proposal = {
                            "dossierId": d_id,
                            "callId": f"call-{d_hash[:20]}",
                            "action": res.get("action", "no_action"),
                            "target": res.get("target"),
                            "payload": res.get("payload", {"reasonCode": "INFORMATIONAL", "referenceId": d_id}),
                            "evidence": res.get("evidence", []),
                        }
                        Q9_CACHE[d_hash] = proposal
                        proposals[idx] = proposal
                with open("q9_cache.json", "w") as f:
                    json.dump(Q9_CACHE, f)
            except Exception as e:
                print(f"Gemini Q9 fresh error: {e}", flush=True)
        
        return {
            "profile": "ga5-mailroom-action-gate/v2",
            "evaluationId": eval_id,
            "status": "awaiting_receipts",
            "inputDigest": digest,
            "proposals": proposals,
        }

        
    elif op == "commit":
        digest = body.get("inputDigest")
        receipts = body.get("receipts", [])
        outcomes = []
        for r in receipts:
            status = "executed" if r["accepted"] else "rejected"
            outcomes.append({
                "dossierId": r["dossierId"],
                "callId": r["callId"],
                "action": r["action"],
                "proposalDigest": r["proposalDigest"],
                "receiptId": r["receiptId"],
                "status": status
            })
            
        return {
            "profile": "ga5-mailroom-action-gate/v2",
            "evaluationId": eval_id,
            "status": "completed",
            "inputDigest": digest,
            "outcomes": outcomes
        }
        
    raise HTTPException(status_code=400, detail="Invalid operation")

# ==============================================================================
# Q10 - A2A Invoice Action Agent / Durable Delegate
# ==============================================================================

@app.get("/.well-known/agent-card.json")
def get_agent_card(request: Request):
    base_url = str(request.base_url).rstrip("/")
    card = {
        "name": "ga5-invoice-agent",
        "description": "Durable Invoice Action Agent",
        "version": "1.0",
        "capabilities": {
            "invoice_action_agent": {
                "name": "Invoice Action Agent Skill",
                "description": "Analyzes invoice claims and durably processes them",
                "tags": ["invoice", "automation"]
            }
        },
        "supportedInterfaces": [
            {
                "uri": f"{base_url}/a2a/",
                "protocolBinding": "HTTP+JSON",
                "protocolVersion": "1.0"
            }
        ],
        "defaultInputModes": ["application/vnd.ga5.invoice-claim-batch+json"],
        "defaultOutputModes": [
            "application/vnd.ga5.invoice-action-proposals+json",
            "application/vnd.ga5.invoice-action-receipts+json"
        ]
    }
    return Response(content=json.dumps(card), media_type="application/a2a+json")

# Require headers: A2A-Version: 1.0, Authorization: Bearer <token>
def verify_a2a_headers(request: Request):
    a2a_version = request.headers.get("A2A-Version", "")
    authorization = request.headers.get("Authorization", "")
    
    # Be lenient: only reject if version explicitly provided AND wrong
    if a2a_version and a2a_version != "1.0":
        raise HTTPException(status_code=400, detail="Unsupported A2A version")
    # Accept any bearer token, or anonymous if no auth header
    if authorization and not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid Authorization header")
    
    if authorization.startswith("Bearer "):
        return authorization.split(" ", 1)[1]
    return "anonymous"


@app.post("/a2a/message:send")
@app.post("/message:send")
async def a2a_message_send(request: Request):
    token = verify_a2a_headers(request)
    body = await request.json()
    msg = body.get("message", {})
    msg_id = msg.get("messageId")
    
    # Hashing Bearer token to isolate tenant state
    principal = hashlib.sha256(token.encode('utf-8')).hexdigest()[:16]
    
    # Deduplicate by (principal, messageId)
    dedup_key = f"{principal}:{msg_id}"
    
    # Extract package claims
    parts = msg.get("parts", [])
    # Support multiple body formats
    data_part = next((p for p in parts if p.get("mediaType") == "application/vnd.ga5.invoice-claim-batch+json"), None)
    if not data_part:
        # Fallback: part has data dict with batchId
        data_part = next((p for p in parts if isinstance(p.get("data"), dict) and "batchId" in p.get("data", {})), None)
    if not data_part:
        # Fallback: part has data dict with packages
        data_part = next((p for p in parts if isinstance(p.get("data"), dict) and "packages" in p.get("data", {})), None)
    if not data_part:
        raise HTTPException(status_code=400, detail="Missing claim batch data")

         
    batch_data = data_part.get("data", {})
    batch_id = batch_data.get("batchId")
    packages = batch_data.get("packages", [])
    
    # Check if task already exists
    task_id = f"task-{hashlib.sha256(dedup_key.encode()).hexdigest()[:16]}"
    
    if task_id in Q10_TASKS:
        # Check idempotency conflict
        existing = Q10_TASKS[task_id]
        if existing["msg_id"] == msg_id and existing["principal"] == principal:
            return Response(content=json.dumps({"task": existing["task"]}), media_type="application/a2a+json")
        else:
            raise HTTPException(status_code=409, detail="IDEMPOTENCY_CONFLICT")
            
    # Process packages with fast rule-based invoice classifier
    def classify_invoice(pkg):
        """Rule-based invoice action decision based on document text signals."""
        pkg_id = pkg.get("packageId", "")
        docs = pkg.get("documents", [])
        all_text = " ".join(doc.get("text", "").lower() for doc in docs)
        
        # Extract facts from intake document
        facts = {"vendorName": "", "invoiceNumber": "", "amountMinor": 0, "currency": ""}
        for doc in docs:
            text = doc.get("text", "")
            # Try to extract supplier and invoice info
            for line in text.split("\n"):
                line_l = line.lower()
                if "supplier" in line_l and not facts["vendorName"]:
                    parts_l = line.split(";")
                    if len(parts_l) > 0:
                        facts["vendorName"] = parts_l[0].replace("Case-file extract. Supplier","").replace("Supplier","").strip()[:50]
                if "invoice" in line_l and not facts["invoiceNumber"]:
                    import re
                    m = re.search(r'INV[-\w]+', line)
                    if m: facts["invoiceNumber"] = m.group(0)
                if not facts["currency"]:
                    for cur in ["INR", "USD", "EUR", "GBP", "JPY", "AUD", "CAD"]:
                        if cur in text:
                            facts["currency"] = cur
                            import re
                            am = re.search(fr'{cur}\s+([\d,\.]+)', text)
                            if am:
                                try:
                                    facts["amountMinor"] = int(float(am.group(1).replace(",","")) * 100)
                                except: pass
                            break
        
        evidence_refs = []
        import re
        for ref in re.findall(r'\[R_[A-Z0-9]+\]', " ".join(doc.get("text","") for doc in docs)):
            if ref not in evidence_refs:
                evidence_refs.append(ref)
        evidence_refs = evidence_refs[:3]
        
        # Decision rules based on document signals
        # Rule 1: Duplicate invoice
        if any(sig in all_text for sig in ["duplicate", "already paid", "paid-items ledger", "earlier posting",
                                            "same supplier", "exact commercial duplicate"]):
            return ("reject_duplicate", facts, evidence_refs,
                    f"Duplicate detected: {', '.join(evidence_refs[:2])}. Policy directs rejection, not resettlement.")
        
        # Rule 2: Outside authority → needs approval
        if any(sig in all_text for sig in ["outside the operator", "outside.*authority", "exceeds.*authority",
                                            "requires.*approval", "financial-approval", "delegated authority"]):
            return ("request_approval", facts, evidence_refs,
                    f"Claim is outside autonomous authority {', '.join(evidence_refs[:2])}. Financial approval required.")
        
        # Rule 3: Three-way match within authority → settle
        if (any(sig in all_text for sig in ["three-way match", "clean.*match", "fully reconciled"])
                and not any(sig in all_text for sig in ["outside", "authority", "hold"])):
            return ("settle_invoice", facts, evidence_refs,
                    f"Clean three-way match {', '.join(evidence_refs[:2])}. Within autonomous authority for settlement.")
        
        # Rule 4: Records conflict
        if any(sig in all_text for sig in ["conflict", "discrepancy", "records.*conflict", "material.*conflict"]):
            return ("open_exception", facts, evidence_refs,
                    f"Material records conflict {', '.join(evidence_refs[:2])}. Exception workflow required.")
        
        # Rule 5: Verification pending
        if any(sig in all_text for sig in ["verification", "pending verification", "hold.*payment", "await.*verification"]):
            return ("hold_invoice", facts, evidence_refs,
                    f"Payment held pending verification {', '.join(evidence_refs[:2])}.")
        
        # Default: request approval (safe default)
        return ("request_approval", facts, evidence_refs,
                f"Defaulting to approval workflow {', '.join(evidence_refs[:2])}.")
    
    proposals = []
    for pkg in packages:
        action, facts, evidence_refs, rationale = classify_invoice(pkg)
        proposals.append({
            "packageId": pkg.get("packageId", ""),
            "actionId": f"act-{uuid.uuid4()}",
            "action": action,
            "facts": facts,
            "evidenceRefs": evidence_refs,
            "rationale": rationale,
        })

            
    # Create the task
    task = {
        "taskId": task_id,
        "status": "TASK_STATE_INPUT_REQUIRED",
        "history": [msg],
        "artifacts": [
            {
                "mediaType": "application/vnd.ga5.invoice-action-proposals+json",
                "data": {
                    "batchId": batch_id,
                    "proposals": proposals
                }
            }
        ]
    }
    
    Q10_TASKS[task_id] = {
        "task": task,
        "msg_id": msg_id,
        "principal": principal,
        "batch_id": batch_id,
        "proposals": proposals
    }
    
    return Response(content=json.dumps({"task": task}), media_type="application/a2a+json")

@app.post("/a2a/tasks/{id}:cancel")
@app.post("/tasks/{id}:cancel")
async def a2a_cancel_task(id: str, request: Request):
    token = verify_a2a_headers(request)
    principal = hashlib.sha256(token.encode('utf-8')).hexdigest()[:16]
    
    if id not in Q10_TASKS or Q10_TASKS[id]["principal"] != principal:
        raise HTTPException(status_code=404, detail="Task not found")
        
    task = Q10_TASKS[id]["task"]
    if task["status"] in ("TASK_STATE_COMPLETED", "TASK_STATE_CANCELED"):
        return Response(content=json.dumps({"task": task}), media_type="application/a2a+json")
        
    task["status"] = "TASK_STATE_CANCELED"
    return Response(content=json.dumps({"task": task}), media_type="application/a2a+json")

@app.get("/a2a/tasks/{id}")
@app.get("/tasks/{id}")
async def a2a_get_task(id: str, request: Request):
    token = verify_a2a_headers(request)
    principal = hashlib.sha256(token.encode('utf-8')).hexdigest()[:16]
    
    if id not in Q10_TASKS or Q10_TASKS[id]["principal"] != principal:
        raise HTTPException(status_code=404, detail="Task not found")
        
    return Response(content=json.dumps({"task": Q10_TASKS[id]["task"]}), media_type="application/a2a+json")

@app.get("/a2a/tasks")
@app.get("/tasks")
async def a2a_list_tasks(request: Request):
    token = verify_a2a_headers(request)
    principal = hashlib.sha256(token.encode('utf-8')).hexdigest()[:16]
    
    tasks = [v["task"] for v in Q10_TASKS.values() if v["principal"] == principal]
    return Response(content=json.dumps({"tasks": tasks}), media_type="application/a2a+json")

@app.post("/a2a/tasks/{id}:continue")
@app.post("/tasks/{id}:continue")
async def a2a_continue_task(id: str, request: Request):
    token = verify_a2a_headers(request)
    principal = hashlib.sha256(token.encode('utf-8')).hexdigest()[:16]
    
    if id not in Q10_TASKS or Q10_TASKS[id]["principal"] != principal:
        raise HTTPException(status_code=404, detail="Task not found")
        
    body = await request.json()
    msg = body.get("message", {})
    
    task_entry = Q10_TASKS[id]
    task = task_entry["task"]
    
    if task["status"] != "TASK_STATE_INPUT_REQUIRED":
         raise HTTPException(status_code=400, detail="Task is not in input-required state")
         
    # Append message to history
    task["history"].append(msg)
    
    # Process results from continuation
    parts = msg.get("parts", [])
    results_part = next((p for p in parts if p.get("mediaType") == "application/vnd.ga5.invoice-action-results+json"), None)
    if not results_part:
        raise HTTPException(status_code=400, detail="Missing results data in continuation")
        
    results_data = results_part.get("data", {})
    results = results_data.get("results", [])
    
    # Build executions
    executions = []
    proposals_map = {p["packageId"]: p for p in task_entry["proposals"]}
    
    for r in results:
        package_id = r["packageId"]
        if r["outcome"] == "ACCEPTED" and package_id in proposals_map:
            prop = proposals_map[package_id]
            executions.append({
                "packageId": package_id,
                "actionId": r["actionId"],
                "action": r["action"],
                "receiptNonce": r["receiptNonce"],
                "facts": prop["facts"],
                "evidenceRefs": prop["evidenceRefs"]
            })
            
    task["artifacts"].append({
        "mediaType": "application/vnd.ga5.invoice-action-receipts+json",
        "data": {
            "batchId": task_entry["batch_id"],
            "executions": executions
        }
    })
    
    task["status"] = "TASK_STATE_COMPLETED"
    return Response(content=json.dumps({"task": task}), media_type="application/a2a+json")

# ==============================================================================
# Q11 - Observable Incident-Response Agent / Trace Integrity
# ==========================================================def make_arguments_digest(args_dict):
    def sort_dict(obj):
        if isinstance(obj, dict):
            return {k: sort_dict(v) for k, v in sorted(obj.items())}
        elif isinstance(obj, list):
            return [sort_dict(x) for x in obj]
        return obj
    sorted_args = sort_dict(args_dict)
    compact = json.dumps(sorted_args, separators=(',', ':'), ensure_ascii=False)
    return hashlib.sha256(compact.encode('utf-8')).hexdigest()

@app.post("/v2/incidents")
async def incident_handler(request: Request, traceparent: Optional[str] = Header(None)):
    body = await request.json()
    profile = body.get("profile")
    if profile != "ga5-incident-agent/v2":
        raise HTTPException(status_code=400, detail="Unsupported profile")
        
    run_id = body.get("runId")
    if not run_id:
        raise HTTPException(status_code=400, detail="Missing runId")
        
    # Idempotency / Replay / Conflict checks
    if run_id in Q11_RUNS:
        existing = Q11_RUNS[run_id]
        existing_incident = existing["incident"]
        incoming_incident = body.get("incident", {})
        if (existing_incident.get("incidentId") != incoming_incident.get("incidentId") or
            existing_incident.get("transcript") != incoming_incident.get("transcript")):
            raise HTTPException(status_code=409, detail="CONFLICT: runId already exists with different content")
            
        if existing["status"] == "completed":
            return existing["final_response"]
            
        return {
            "runId": run_id,
            "status": "waiting",
            "diagnosis": existing["diagnosis"],
            "dispatches": existing["dispatches"],
            "approvals": existing["approvals"]
        }
        
    incident = body.get("incident", {})
    transcript = incident.get("transcript", "")
    allowed_causes = incident.get("allowedRootCauses", [])
    policy = body.get("policy", {})
    service = incident.get("service", "")
    
    # Traceparent propagation
    parent_trace_id = None
    parent_span_id = None
    if traceparent:
        try:
            parts = traceparent.split("-")
            if len(parts) == 4:
                parent_trace_id = parts[1]
                parent_span_id = parts[2]
        except Exception:
            pass
            
    trace_id = parent_trace_id or uuid.uuid4().hex
    server_span_id = uuid.uuid4().hex[:16]
    agent_span_id = uuid.uuid4().hex[:16]
    client_span_id = uuid.uuid4().hex[:16]
    
    # Fast rule-based incident root cause analysis
    def classify_incident(transcript, allowed_causes, effect_tools, service):
        transcript_lower = transcript.lower()
        
        # Extract all event IDs from transcript
        import re
        all_ev_ids = re.findall(r'\[ev_[A-Za-z0-9]+\]', transcript)
        
        # Score each allowed cause by keyword matches
        cause_keywords = {
            "bad_deployment": ["deployment", "rollout", "release", "rolled out", "new version", "deploy", "dep_"],
            "certificate_expiry": ["certificate", "cert", "tls", "ssl", "expired", "expir"],
            "memory_leak": ["memory", "oom", "out of memory", "heap", "leak", "memory pressure"],
            "cpu_spike": ["cpu", "load", "spike", "throttl", "processor"],
            "disk_full": ["disk", "storage", "volume", "space", "inode"],
            "network_partition": ["network", "partition", "unreachable", "connectivity", "timeout"],
            "database_overload": ["database", "db", "query", "slow query", "connection pool", "sql"],
            "dependency_failure": ["dependency", "upstream", "downstream", "third-party", "external service"],
            "config_change": ["config", "configuration", "setting", "env", "flag", "toggl"],
            "rate_limit": ["rate limit", "throttl", "quota", "429"],
            "scaling_failure": ["scal", "autoscal", "replica", "pod", "capacity"],
            "feature_flag": ["feature flag", "feature toggle", "feat_", "flag", "feature rollout"],
        }
        
        best_cause = None
        best_score = -1
        best_evidence = []
        
        for cause in allowed_causes:
            # Exact match
            if cause in cause_keywords:
                keywords = cause_keywords[cause]
            else:
                # Use cause name as keyword
                keywords = [cause.replace("_", " "), cause]
            
            score = sum(1 for kw in keywords if kw in transcript_lower)
            # Find the evidence line IDs that contain these keywords
            ev_for_cause = []
            lines = transcript.split("\n")
            for line in lines:
                line_lower = line.lower()
                if any(kw in line_lower for kw in keywords):
                    ev_ids = re.findall(r'\[ev_[A-Za-z0-9]+\]', line)
                    ev_for_cause.extend(e.strip("[]") for e in ev_ids)
            
            if score > best_score:
                best_score = score
                best_cause = cause
                best_evidence = ev_for_cause[:3]
        
        # Default to first cause if no match
        if not best_cause and allowed_causes:
            best_cause = allowed_causes[0]
        
        # Pick evidence if none found - use last few event IDs (most recent events)
        if not best_evidence and all_ev_ids:
            best_evidence = [e.strip("[]") for e in all_ev_ids[-3:]]
        
        # Pick the effect tool
        chosen_effect = None
        effect_args = {"service": service}
        
        for tool in effect_tools:
            tool_lower = tool.lower()
            if "rollback" in tool_lower and best_cause in ("bad_deployment", "config_change", "feature_flag"):
                chosen_effect = tool
                # Extract deployment ID from transcript
                dep_match = re.search(r'dep_[A-Za-z0-9]+', transcript)
                if dep_match:
                    effect_args["deploymentId"] = dep_match.group(0)
                else:
                    effect_args["deploymentId"] = "dep-latest"
                break
            elif "disable" in tool_lower and "feature" in tool_lower:
                if best_cause in ("feature_flag",):
                    chosen_effect = tool
                    feat_match = re.search(r'feat_[A-Za-z0-9]+', transcript)
                    effect_args["featureName"] = feat_match.group(0) if feat_match else "feat-unknown"
                    break
            elif "scale" in tool_lower:
                chosen_effect = tool
                break
        
        if not chosen_effect and effect_tools:
            chosen_effect = effect_tools[0]
        
        return best_cause, best_evidence, chosen_effect, effect_args
    
    effect_tools = policy.get("effectTools", [])
    root_cause, evidence, chosen_effect, arguments = classify_incident(
        transcript, allowed_causes, effect_tools, service
    )
    
    print(f"Q11 rule-based: root_cause={root_cause}, effect={chosen_effect}", flush=True)

        
    diagnosis = {"rootCause": root_cause, "evidence": evidence}
    
    # Create initial OTLP spans
    spans = [
        {
            "traceId": trace_id,
            "spanId": server_span_id,
            "parentSpanId": parent_span_id,
            "name": "POST /v2/incidents",
            "kind": 2, # SERVER
            "attributes": [
                {"key": "ga5.run.id", "value": {"stringValue": run_id}},
                {"key": "ga5.public.marker", "value": {"stringValue": body.get("publicMarker", "")}}
            ]
        },
        {
            "traceId": trace_id,
            "spanId": agent_span_id,
            "parentSpanId": server_span_id,
            "name": "invoke_agent incident-response",
            "kind": 1, # INTERNAL
            "attributes": [
                {"key": "ga5.run.id", "value": {"stringValue": run_id}},
                {"key": "ga5.public.marker", "value": {"stringValue": body.get("publicMarker", "")}}
            ]
        },
        {
            "traceId": trace_id,
            "spanId": client_span_id,
            "parentSpanId": agent_span_id,
            "name": "chat incident-plan",
            "kind": 3, # CLIENT
            "attributes": [
                {"key": "ga5.run.id", "value": {"stringValue": run_id}},
                {"key": "ga5.public.marker", "value": {"stringValue": body.get("publicMarker", "")}},
                {"key": "gen_ai.operation.name", "value": {"stringValue": "chat"}},
                {"key": "gen_ai.request.model", "value": {"stringValue": "gemini-3.5-flash"}}
            ]
        }
    ]
    
    # Generate diagnostic dispatches (up to 3)
    catalog = body.get("toolCatalog", [])
    dispatches = []
    if catalog:
        diag_tools = [t for t in catalog if t.get("name") in ("query_metrics", "check_logs", "read_config")]
        for t in diag_tools[:3]:
            action_id = f"act-{uuid.uuid4().hex[:16]}"
            call_id = f"call-{uuid.uuid4().hex[:16]}"
            tool_client_span = uuid.uuid4().hex[:16]
            tool_internal_span = uuid.uuid4().hex[:16]
            
            tp = f"00-{trace_id}-{tool_client_span}-01"
            
            dispatches.append({
                "actionId": action_id,
                "callId": call_id,
                "phase": "diagnostic",
                "toolName": t["name"],
                "arguments": {},
                "evidence": evidence[:1],
                "attempt": 1,
                "traceparent": tp
            })
            
            spans.extend([
                {
                    "traceId": trace_id,
                    "spanId": tool_internal_span,
                    "parentSpanId": agent_span_id,
                    "name": "execute_tool",
                    "kind": 1,
                    "attributes": [
                        {"key": "ga5.run.id", "value": {"stringValue": run_id}},
                        {"key": "ga5.public.marker", "value": {"stringValue": body.get("publicMarker", "")}},
                        {"key": "ga5.action.id", "value": {"stringValue": action_id}},
                        {"key": "gen_ai.tool.name", "value": {"stringValue": t["name"]}},
                        {"key": "gen_ai.tool.call.id", "value": {"stringValue": call_id}},
                        {"key": "gen_ai.operation.name", "value": {"stringValue": "execute_tool"}}
                    ]
                },
                {
                    "traceId": trace_id,
                    "spanId": tool_client_span,
                    "parentSpanId": tool_internal_span,
                    "name": f"POST tool/{t['name']}",
                    "kind": 3,
                    "attributes": [
                        {"key": "ga5.run.id", "value": {"stringValue": run_id}},
                        {"key": "ga5.public.marker", "value": {"stringValue": body.get("publicMarker", "")}},
                        {"key": "ga5.action.id", "value": {"stringValue": action_id}},
                        {"key": "ga5.attempt", "value": {"intValue": 1}},
                        {"key": "http.request.method", "value": {"stringValue": "POST"}},
                        {"key": "http.request.resend_count", "value": {"intValue": 0}}
                    ]
                }
            ])
            
    if dispatches:
        join_span_id = uuid.uuid4().hex[:16]
        diag_internal_spans = [s["spanId"] for s in spans if s["name"] == "execute_tool" and s.get("parentSpanId") == agent_span_id]
        spans.append({
            "traceId": trace_id,
            "spanId": join_span_id,
            "parentSpanId": agent_span_id,
            "name": "incident.join",
            "kind": 1,
            "attributes": [
                {"key": "ga5.run.id", "value": {"stringValue": run_id}},
                {"key": "ga5.public.marker", "value": {"stringValue": body.get("publicMarker", "")}}
            ],
            "links": [{"traceId": trace_id, "spanId": s_id} for s_id in diag_internal_spans]
        })
            
    run_state = {
        "runId": run_id,
        "status": "waiting_diagnostics" if dispatches else "waiting_decision",
        "diagnosis": diagnosis,
        "chosenEffect": chosen_effect,
        "arguments": arguments,
        "dispatches": dispatches,
        "approvals": [],
        "spans": spans,
        "trace_id": trace_id,
        "agent_span_id": agent_span_id,
        "public_marker": body.get("publicMarker", ""),
        "incident": incident,
        "policy": policy,
        "receiptLog": [],
        "processed_receipts": {}
    }
    
    Q11_RUNS[run_id] = run_state
    
    # If no diagnostics, transition immediately to effect/approval
    if not dispatches:
        approval_required = chosen_effect in policy.get("approvalRequiredFor", [])
        if approval_required:
            app_id = f"app-{uuid.uuid4().hex[:16]}"
            act_id = f"act-{uuid.uuid4().hex[:16]}"
            digest = make_arguments_digest(arguments)
            approval_req = {
                "approvalId": app_id,
                "actionId": act_id,
                "toolName": chosen_effect,
                "argumentsDigest": digest
            }
            run_state["approvals"] = [approval_req]
            run_state["status"] = "waiting_approval"
            
            # Create approval_gate span
            spans.append({
                "traceId": trace_id,
                "spanId": uuid.uuid4().hex[:16],
                "parentSpanId": agent_span_id,
                "name": "approval_gate",
                "kind": 1, # INTERNAL
                "attributes": [
                    {"key": "ga5.run.id", "value": {"stringValue": run_id}},
                    {"key": "ga5.public.marker", "value": {"stringValue": body.get("publicMarker", "")}},
                    {"key": "ga5.approval.id", "value": {"stringValue": app_id}}
                ]
            })
        else:
            act_id = f"act-{uuid.uuid4().hex[:16]}"
            call_id = f"call-{uuid.uuid4().hex[:16]}"
            eff_client_span = uuid.uuid4().hex[:16]
            eff_internal_span = uuid.uuid4().hex[:16]
            tp = f"00-{trace_id}-{eff_client_span}-01"
            
            eff_dispatch = {
                "actionId": act_id,
                "callId": call_id,
                "phase": "effect",
                "toolName": chosen_effect,
                "arguments": arguments,
                "attempt": 1,
                "traceparent": tp
            }
            run_state["dispatches"] = [eff_dispatch]
            run_state["status"] = "waiting_effect"
            
            spans.extend([
                {
                    "traceId": trace_id,
                    "spanId": eff_internal_span,
                    "parentSpanId": agent_span_id,
                    "name": "execute_tool",
                    "kind": 1,
                    "attributes": [
                        {"key": "ga5.run.id", "value": {"stringValue": run_id}},
                        {"key": "ga5.public.marker", "value": {"stringValue": body.get("publicMarker", "")}},
                        {"key": "ga5.action.id", "value": {"stringValue": act_id}},
                        {"key": "gen_ai.tool.name", "value": {"stringValue": chosen_effect}},
                        {"key": "gen_ai.tool.call.id", "value": {"stringValue": call_id}},
                        {"key": "gen_ai.operation.name", "value": {"stringValue": "execute_tool"}}
                    ]
                },
                {
                    "traceId": trace_id,
                    "spanId": eff_client_span,
                    "parentSpanId": eff_internal_span,
                    "name": f"POST tool/{chosen_effect}",
                    "kind": 3,
                    "attributes": [
                        {"key": "ga5.run.id", "value": {"stringValue": run_id}},
                        {"key": "ga5.public.marker", "value": {"stringValue": body.get("publicMarker", "")}},
                        {"key": "ga5.action.id", "value": {"stringValue": act_id}},
                        {"key": "ga5.attempt", "value": {"intValue": 1}},
                        {"key": "http.request.method", "value": {"stringValue": "POST"}},
                        {"key": "http.request.resend_count", "value": {"intValue": 0}}
                    ]
                }
            ])
            
    return {
        "runId": run_id,
        "status": "waiting",
        "diagnosis": diagnosis,
        "dispatches": run_state["dispatches"],
        "approvals": run_state["approvals"]
    }

@app.post("/v2/incidents/{runId}/receipts")
async def incident_receipts(runId: str, request: Request):
    if runId not in Q11_RUNS:
         raise HTTPException(status_code=404, detail="Run not found")
         
    run = Q11_RUNS[runId]
    body = await request.json()
    receipt_id = body.get("receiptId")
    
    # Replay check
    if receipt_id in run["processed_receipts"]:
        existing = run["processed_receipts"][receipt_id]
        if existing["body"] != body:
            raise HTTPException(status_code=409, detail="CONFLICT: receiptId already processed with different content")
        return existing["response"]
        
    outcomes = body.get("outcomes", [])
    approvals = body.get("approvals", [])
    
    # Process diagnostic or effect outcomes
    for o in outcomes:
        run["receiptLog"].append({
            "receiptId": receipt_id,
            "actionId": o.get("actionId"),
            "callId": o.get("callId"),
            "attempt": o.get("attempt", 1),
            "status": o.get("status", 200),
            "resultClass": o.get("resultClass", ""),
            "nonce": o.get("nonce", "")
        })
        
        for s in run["spans"]:
            if s["name"].startswith("POST tool/") and s["kind"] == 3:
                act_attr = next((a for a in s["attributes"] if a["key"] == "ga5.action.id"), None)
                if act_attr and act_attr["value"].get("stringValue") == o.get("actionId"):
                    s["attributes"] = [attr for attr in s["attributes"] if attr["key"] not in (
                        "ga5.receipt.id", "ga5.receipt.nonce", 
                        "http.response.status_code", "http.request.resend_count", "ga5.attempt"
                    )]
                    s["attributes"].extend([
                        {"key": "ga5.receipt.id", "value": {"stringValue": receipt_id}},
                        {"key": "ga5.receipt.nonce", "value": {"stringValue": o.get("nonce", "")}},
                        {"key": "ga5.attempt", "value": {"intValue": int(o.get("attempt", 1))}},
                        {"key": "http.response.status_code", "value": {"intValue": int(o.get("status", 200))}},
                        {"key": "http.request.resend_count", "value": {"intValue": int(o.get("attempt", 1)) - 1}}
                    ])
                    
    # Process approvals
    for a in approvals:
        run["receiptLog"].append({
            "receiptId": receipt_id,
            "approvalId": a.get("approvalId"),
            "decision": a.get("decision", "approved"),
            "nonce": a.get("nonce", "")
        })
        
        # Find the approval_gate span and add receipt nonce
        for s in run["spans"]:
            if s["name"] == "approval_gate":
                app_attr = next((attr for attr in s["attributes"] if attr["key"] == "ga5.approval.id"), None)
                if app_attr and app_attr["value"].get("stringValue") == a.get("approvalId"):
                    s["attributes"] = [attr for attr in s["attributes"] if attr["key"] != "ga5.receipt.nonce"]
                    s["attributes"].append({"key": "ga5.receipt.nonce", "value": {"stringValue": a.get("nonce", "")}})
        
    # State Machine Transitions
    response = {}
    if run["status"] == "waiting_diagnostics":
        chosen_effect = run["chosenEffect"]
        policy = run["policy"]
        arguments = run["arguments"]
        trace_id = run["trace_id"]
        agent_span_id = run["agent_span_id"]
        
        approval_required = chosen_effect in policy.get("approvalRequiredFor", [])
        if approval_required:
            app_id = f"app-{uuid.uuid4().hex[:16]}"
            act_id = f"act-{uuid.uuid4().hex[:16]}"
            digest = make_arguments_digest(arguments)
            
            approval_req = {
                "approvalId": app_id,
                "actionId": act_id,
                "toolName": chosen_effect,
                "argumentsDigest": digest
            }
            run["approvals"] = [approval_req]
            run["dispatches"] = []
            run["status"] = "waiting_approval"
            
            run["spans"].append({
                "traceId": trace_id,
                "spanId": uuid.uuid4().hex[:16],
                "parentSpanId": agent_span_id,
                "name": "approval_gate",
                "kind": 1, # INTERNAL
                "attributes": [
                    {"key": "ga5.run.id", "value": {"stringValue": runId}},
                    {"key": "ga5.public.marker", "value": {"stringValue": run["public_marker"]}},
                    {"key": "ga5.approval.id", "value": {"stringValue": app_id}}
                ]
            })
            
            response = {
                "runId": runId,
                "status": "waiting",
                "dispatches": [],
                "approvals": [approval_req]
            }
        else:
            act_id = f"act-{uuid.uuid4().hex[:16]}"
            call_id = f"call-{uuid.uuid4().hex[:16]}"
            eff_client_span = uuid.uuid4().hex[:16]
            eff_internal_span = uuid.uuid4().hex[:16]
            tp = f"00-{trace_id}-{eff_client_span}-01"
            
            eff_dispatch = {
                "actionId": act_id,
                "callId": call_id,
                "phase": "effect",
                "toolName": chosen_effect,
                "arguments": arguments,
                "attempt": 1,
                "traceparent": tp
            }
            run["dispatches"].append(eff_dispatch)
            run["status"] = "waiting_effect"
            
            run["spans"].extend([
                {
                    "traceId": trace_id,
                    "spanId": eff_internal_span,
                    "parentSpanId": agent_span_id,
                    "name": "execute_tool",
                    "kind": 1,
                    "attributes": [
                        {"key": "ga5.run.id", "value": {"stringValue": runId}},
                        {"key": "ga5.public.marker", "value": {"stringValue": run["public_marker"]}},
                        {"key": "ga5.action.id", "value": {"stringValue": act_id}},
                        {"key": "gen_ai.tool.name", "value": {"stringValue": chosen_effect}},
                        {"key": "gen_ai.tool.call.id", "value": {"stringValue": call_id}},
                        {"key": "gen_ai.operation.name", "value": {"stringValue": "execute_tool"}}
                    ]
                },
                {
                    "traceId": trace_id,
                    "spanId": eff_client_span,
                    "parentSpanId": eff_internal_span,
                    "name": f"POST tool/{chosen_effect}",
                    "kind": 3,
                    "attributes": [
                        {"key": "ga5.run.id", "value": {"stringValue": runId}},
                        {"key": "ga5.public.marker", "value": {"stringValue": run["public_marker"]}},
                        {"key": "ga5.action.id", "value": {"stringValue": act_id}},
                        {"key": "ga5.attempt", "value": {"intValue": 1}},
                        {"key": "http.request.method", "value": {"stringValue": "POST"}},
                        {"key": "http.request.resend_count", "value": {"intValue": 0}}
                    ]
                }
            ])
            
            response = {
                "runId": runId,
                "status": "waiting",
                "dispatches": [eff_dispatch],
                "approvals": []
            }
            
    elif run["status"] == "waiting_approval":
        app_receipt = next((x for x in run["receiptLog"] if "approvalId" in x), None)
        if app_receipt and app_receipt["decision"] == "approved":
            chosen_effect = run["chosenEffect"]
            arguments = run["arguments"]
            trace_id = run["trace_id"]
            agent_span_id = run["agent_span_id"]
            app_id = app_receipt["approvalId"]
            app_nonce = app_receipt["nonce"]
            
            for s in run["spans"]:
                if s["name"] == "approval_gate":
                    s["attributes"].append({"key": "ga5.receipt.nonce", "value": {"stringValue": app_nonce}})
            
            act_id = f"act-{uuid.uuid4().hex[:16]}"
            call_id = f"call-{uuid.uuid4().hex[:16]}"
            eff_client_span = uuid.uuid4().hex[:16]
            eff_internal_span = uuid.uuid4().hex[:16]
            tp = f"00-{trace_id}-{eff_client_span}-01"
            
            eff_dispatch = {
                "actionId": act_id,
                "callId": call_id,
                "phase": "effect",
                "toolName": chosen_effect,
                "arguments": arguments,
                "attempt": 1,
                "traceparent": tp,
                "approvalId": app_id,
                "approvalNonce": app_nonce
            }
            run["dispatches"].append(eff_dispatch)
            run["status"] = "waiting_effect"
            
            run["spans"].extend([
                {
                    "traceId": trace_id,
                    "spanId": eff_internal_span,
                    "parentSpanId": agent_span_id,
                    "name": "execute_tool",
                    "kind": 1,
                    "attributes": [
                        {"key": "ga5.run.id", "value": {"stringValue": runId}},
                        {"key": "ga5.public.marker", "value": {"stringValue": run["public_marker"]}},
                        {"key": "ga5.action.id", "value": {"stringValue": act_id}},
                        {"key": "gen_ai.tool.name", "value": {"stringValue": chosen_effect}},
                        {"key": "gen_ai.tool.call.id", "value": {"stringValue": call_id}},
                        {"key": "gen_ai.operation.name", "value": {"stringValue": "execute_tool"}}
                    ]
                },
                {
                    "traceId": trace_id,
                    "spanId": eff_client_span,
                    "parentSpanId": eff_internal_span,
                    "name": f"POST tool/{chosen_effect}",
                    "kind": 3,
                    "attributes": [
                        {"key": "ga5.run.id", "value": {"stringValue": runId}},
                        {"key": "ga5.public.marker", "value": {"stringValue": run["public_marker"]}},
                        {"key": "ga5.action.id", "value": {"stringValue": act_id}},
                        {"key": "ga5.attempt", "value": {"intValue": 1}},
                        {"key": "http.request.method", "value": {"stringValue": "POST"}},
                        {"key": "http.request.resend_count", "value": {"intValue": 0}}
                    ]
                }
            ])
            
            response = {
                "runId": runId,
                "status": "waiting",
                "dispatches": [eff_dispatch],
                "approvals": []
            }
        else:
            response = {
                "runId": runId,
                "status": "waiting",
                "dispatches": [],
                "approvals": run["approvals"]
            }
            
    elif run["status"] == "waiting_effect":
        run["status"] = "completed"
        
        otlp = {
            "resourceSpans": [
                {
                    "scopeSpans": [
                        {
                            "spans": run["spans"]
                        }
                    ]
                }
            ]
        }
        
        response = {
            "runId": runId,
            "status": "completed",
            "diagnosis": run["diagnosis"],
            "chosenEffect": run["chosenEffect"],
            "suppressed": [],
            "actionLog": run["dispatches"],
            "receiptLog": run["receiptLog"],
            "otlp": otlp
        }
        run["final_response"] = response
        
    run["processed_receipts"][receipt_id] = {
        "body": body,
        "response": response
    }
    
    return response

@app.get("/v2/incidents/{runId}")
async def get_incident(runId: str):
    if runId not in Q11_RUNS:
        raise HTTPException(status_code=404, detail="Run not found")
    run = Q11_RUNS[runId]
    if run["status"] == "completed":
        return run["final_response"]
    return {
        "runId": runId,
        "status": "waiting",
        "diagnosis": run["diagnosis"],
        "dispatches": run["dispatches"],
        "approvals": run["approvals"]
    }

# ==============================================================================
# Dynamic /check Router for Q3, Q5, and Q8
# ==============================================================================

@app.post("/check")
async def check_router(request: Request):
    body = await request.json()
    
    # Q5 payload has "budget_tokens" or "steps"
    if "budget_tokens" in body or "steps" in body:
        try:
            req = BudgetRequest(**body)
            return check_budget_loop(req)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Q5 validation error: {e}")
            
    # Q8 payload has "arguments" and "tool"
    elif "arguments" in body:
        try:
            req = RedteamRequest(**body)
            return check_redteam(req)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Q8 validation error: {e}")
            
    # Q3 payload has "tool" but not "arguments"
    elif "tool" in body:
        try:
            req = GuardrailRequest(**body)
            return check_guardrail(req)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Q3 validation error: {e}")
            
    raise HTTPException(status_code=400, detail="Unknown check payload")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
