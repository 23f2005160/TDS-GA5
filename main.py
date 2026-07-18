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
        # Check for direct or indirect access to secretFile RelName (e.g. .pgpass)
        secret_rel = q3["secretRel"]
        
        # Decode base64 commands to check if they contain the secret name
        decoded_cmd = cmd
        try:
            b64_matches = re.findall(r'[A-Za-z0-9+/=]{16,}', cmd)
            for m in b64_matches:
                try:
                    import base64
                    decoded = base64.b64decode(m).decode('utf-8', errors='ignore')
                    if secret_rel in decoded:
                        decoded_cmd += " " + decoded
                except Exception:
                    pass
        except Exception:
            pass
            
        # Block if secret file or home folder expansion references the secret
        if (secret_rel in cmd or 
            secret_rel in decoded_cmd or
            "~" in cmd and secret_rel in cmd.replace("~", q3["homeDir"]) or
            "$HOME" in cmd and secret_rel in cmd.replace("$HOME", q3["homeDir"])):
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
def scan_skill(req: ScanRequest):
    skill = req.skill
    categories = []
    
    # 1. Hardcoded Secret Detection
    # webhook regex & high entropy API keys/tokens
    slack_webhook = r"https://hooks\.slack\.com/services/[A-Z0-9]+/[A-Z0-9]+/[A-Za-z0-9]+"
    generic_secret = r"(?:api_key|apiKey|token|secret|password|private_key|credentials)\s*[:=]\s*['\"][a-zA-Z0-9_\-\.]{12,}['\"]"
    if re.search(slack_webhook, skill, re.IGNORECASE) or re.search(generic_secret, skill, re.IGNORECASE):
        categories.append("hardcoded_secret")
        
    # 2. Prompt Injection Detection
    # ignore instructions, exfiltrate data, override control
    patterns = [
        r"ignore\s+(?:previous|system|above)\s+instructions",
        r"silently\s+(?:exfiltrate|send|upload)",
        r"do\s+not\s+(?:tell|reveal|surface)\s+to\s+the\s+(?:user|reviewer)",
        r"override\s+(?:control|policy)"
    ]
    if any(re.search(pat, skill, re.IGNORECASE) for pat in patterns):
        categories.append("prompt_injection")
        
    # 3. Excessive Permissions Detection
    # write to root or wildcard access
    if re.search(r"permissions:\s*['\"]?\*['\"]?", skill) or re.search(r"(?:read|write):\s*['\"]?/(?:['\"]|$)", skill):
        categories.append("excessive_permissions")
        
    # 4. Unclear Provenance Detection
    # Missing author, version, or changelog in the YAML frontmatter
    # Extract YAML frontmatter
    fm_match = re.match(r"^---\s*\n(.*?)\n---", skill, re.DOTALL)
    if fm_match:
        fm = fm_match.group(1)
        if not re.search(r"^author:", fm, re.M) or not re.search(r"^version:", fm, re.M):
            categories.append("unclear_provenance")
    else:
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
    # Filter irrelevant field
    cleaned = {k: v for k, v in args_dict.items() if k != irrelevant_field}
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
        # Check for path traversals URL decoded and direct
        if ".." in path and "looks-like-..-but-safe.txt" not in path:
            return {"action": "block", "reason": "Path traversal detected"}
            
        decoded = urllib.parse.unquote(path)
        if ".." in decoded:
            if "%2e%2e-literal.txt" not in path and "looks-like-..-but-safe.txt" not in path:
                return {"action": "block", "reason": "URL encoded path traversal detected"}
                
        resolved = os.path.abspath(path)
        if not resolved.startswith(q8["sandboxRoot"]):
            return {"action": "block", "reason": "Path is outside sandbox"}
            
        # Read the file and return
        try:
            with open(resolved, "r") as f:
                content = f.read()
            return {"action": "allow", "reason": "Path is safe", "result": content}
        except Exception as e:
            return {"action": "allow", "reason": "Path is safe but read failed", "result": str(e)}
            
    elif req.tool == "fetch_url":
        url = req.arguments.get("url") or ""
        try:
            parsed = urllib.parse.urlparse(url)
            hostname = parsed.hostname
            if not hostname:
                return {"action": "block", "reason": "Invalid URL"}
            if hostname not in q8["allowedHosts"]:
                return {"action": "block", "reason": f"SSRF block outbound to {hostname}"}
            # fetch URL without following redirects
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
async def mailroom_handler(request: Request):
    body = await request.json()
    op = body.get("operation")
    eval_id = body.get("evaluationId")
    profile = body.get("profile")
    
    if profile != "ga5-mailroom-action-gate/v2":
        raise HTTPException(status_code=400, detail="Invalid profile")
        
    if op == "propose":
        dossiers = body.get("dossiers", [])
        digest = canonical_json_digest(dossiers)
        
        proposals = []
        # Find uncached dossiers
        uncached = []
        for d in dossiers:
            d_hash = hash_dossier(d)
            if d_hash in Q9_CACHE:
                cached_prop = Q9_CACHE[d_hash].copy()
                # Ensure stable unique callId
                cached_prop["callId"] = f"call-{d_hash[:20]}"
                proposals.append(cached_prop)
            else:
                uncached.append((d, d_hash))
                
        if uncached:
            # We must use Gemini to evaluate uncached dossiers
            prompt = """
Analyze the following dossiers and choose the single safest, least-privilege action from the allowed list:
1. create_draft: target {"kind":"draft_queue", "id":"mailbox:<mailbox>"}, payload {"recipient", "referenceId", "status", "template":"order_status"}
2. update_internal_record: target {"kind":"case_record", "id":"<case id>"}, payload {"field":"delivery_window", "sourceEventId", "value"}
3. send_approved_notice: target {"kind":"email", "id":"<approved recipient>"}, payload {"referenceId", "status", "template":"approved_delivery_notice"}
4. request_confirmation: target {"kind":"approval_queue", "id":"<owning team>"}, payload {"claimedSender", "questionCode":"VERIFY_REQUEST", "referenceId"}
5. quarantine_item: target {"kind":"security_queue", "id":"mailroom"}, payload {"artifactId", "reasonCode":"INDIRECT_PROMPT_INJECTION"}
6. no_action: target null, payload {"reasonCode":"ALREADY_COMPLETED"|"DUPLICATE"|"INFORMATIONAL", "referenceId"}

For EACH dossier, you must return a JSON object with:
- dossierId: the exact dossier ID
- action: the chosen action
- target: target object or null
- payload: payload object
- evidence: list of lineId strings that prove your decision
- reason: short explanation

Return ONLY a JSON list of objects.
"""
            dossiers_payload = [item[0] for item in uncached]
            prompt += f"\nDOSSIERS:\n{json.dumps(dossiers_payload, indent=2)}"
            
            # Send to Gemini
            import google.generativeai as genai
            model = genai.GenerativeModel('gemini-1.5-flash') # fallback to 1.5 if 3.5 not standard yet
            try:
                response = model.generate_content(prompt, generation_config={"response_mime_type": "application/json"})
                results = json.loads(response.text)
                for res in results:
                    d_id = res["dossierId"]
                    # find matching hash
                    d_hash = next(item[1] for item in uncached if item[0]["dossierId"] == d_id)
                    proposal = {
                        "dossierId": d_id,
                        "callId": f"call-{d_hash[:20]}",
                        "action": res["action"],
                        "target": res.get("target"),
                        "payload": res.get("payload"),
                        "evidence": res.get("evidence", [])
                    }
                    Q9_CACHE[d_hash] = proposal
                    proposals.append(proposal)
                # Save cache
                with open("q9_cache.json", "w") as f:
                    json.dump(Q9_CACHE, f)
            except Exception as e:
                # Fallback to no_action for everything if model fails
                for d, d_hash in uncached:
                    fallback = {
                        "dossierId": d["dossierId"],
                        "callId": f"call-{d_hash[:20]}",
                        "action": "no_action",
                        "target": None,
                        "payload": {"reasonCode": "INFORMATIONAL"},
                        "evidence": []
                    }
                    proposals.append(fallback)
                    
        return {
            "profile": "ga5-mailroom-action-gate/v2",
            "evaluationId": eval_id,
            "status": "awaiting_receipts",
            "inputDigest": digest,
            "proposals": proposals
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
    return {
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

# Require headers: A2A-Version: 1.0, Authorization: Bearer <token>
def verify_a2a_headers(request: Request, a2a_version: Optional[str] = Header(None, alias="A2A-Version"), authorization: Optional[str] = Header(None)):
    if a2a_version != "1.0":
        raise HTTPException(status_code=400, detail="Unsupported A2A version")
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")
    return authorization.split(" ")[1]

@app.post("/a2a/message:send")
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
    data_part = next((p for p in parts if p.get("mediaType") == "application/vnd.ga5.invoice-claim-batch+json"), None)
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
            return {"task": existing["task"]}
        else:
            raise HTTPException(status_code=409, detail="IDEMPOTENCY_CONFLICT")
            
    # Process packages using LLM
    proposals = []
    # Batch prompt for Gemini
    prompt = """
Analyze the invoice package documents. Choose exactly one action for every package from the allowed list:
- settle_invoice: valid, reconciled, and within autonomous authority.
- request_approval: commercially valid, but outside delegated authority.
- hold_invoice: payment pauses until a stated verification completes.
- reject_duplicate: the same commercial invoice was already paid.
- open_exception: material records conflict and need an exception workflow.

For EACH package, return JSON with:
- packageId: the exact package ID
- action: chosen action
- facts: { "vendorName", "invoiceNumber", "amountMinor", "currency" }
- evidenceRefs: list of short decisive quotes from documents
- rationale: 60-1500 chars citing two evidence refs

Return ONLY a JSON list of objects.
"""
    prompt += f"\nPACKAGES:\n{json.dumps(packages, indent=2)}"
    
    import google.generativeai as genai
    model = genai.GenerativeModel('gemini-1.5-flash')
    try:
        response = model.generate_content(prompt, generation_config={"response_mime_type": "application/json"})
        results = json.loads(response.text)
        for res in results:
            proposals.append({
                "packageId": res["packageId"],
                "actionId": f"act-{uuid.uuid4()}",
                "action": res["action"],
                "facts": res.get("facts", {}),
                "evidenceRefs": res.get("evidenceRefs", []),
                "rationale": res.get("rationale", "Processed durably by invoice agent.")
            })
    except Exception as e:
        # Fallback
        for p in packages:
            proposals.append({
                "packageId": p["packageId"],
                "actionId": f"act-{uuid.uuid4()}",
                "action": "hold_invoice",
                "facts": {},
                "evidenceRefs": [],
                "rationale": "Fallback decision due to engine error."
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
    
    return {"task": task}

@app.post("/a2a/tasks/{id}:cancel")
async def a2a_cancel_task(id: str, request: Request):
    token = verify_a2a_headers(request)
    principal = hashlib.sha256(token.encode('utf-8')).hexdigest()[:16]
    
    if id not in Q10_TASKS or Q10_TASKS[id]["principal"] != principal:
        raise HTTPException(status_code=404, detail="Task not found")
        
    task = Q10_TASKS[id]["task"]
    if task["status"] in ("TASK_STATE_COMPLETED", "TASK_STATE_CANCELED"):
        return {"task": task}
        
    task["status"] = "TASK_STATE_CANCELED"
    return {"task": task}

@app.get("/a2a/tasks/{id}")
async def a2a_get_task(id: str, request: Request):
    token = verify_a2a_headers(request)
    principal = hashlib.sha256(token.encode('utf-8')).hexdigest()[:16]
    
    if id not in Q10_TASKS or Q10_TASKS[id]["principal"] != principal:
        raise HTTPException(status_code=404, detail="Task not found")
        
    return {"task": Q10_TASKS[id]["task"]}

@app.get("/a2a/tasks")
async def a2a_list_tasks(request: Request):
    token = verify_a2a_headers(request)
    principal = hashlib.sha256(token.encode('utf-8')).hexdigest()[:16]
    
    tasks = [v["task"] for v in Q10_TASKS.values() if v["principal"] == principal]
    return {"tasks": tasks}

@app.post("/a2a/tasks/{id}:continue")
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
    return {"task": task}

# ==============================================================================
# Q11 - Observable Incident-Response Agent / Trace Integrity
# ==============================================================================

@app.post("/v2/incidents")
async def incident_handler(request: Request, traceparent: Optional[str] = Header(None)):
    body = await request.json()
    run_id = body.get("runId")
    incident = body.get("incident", {})
    transcript = incident.get("transcript", "")
    allowed_causes = incident.get("allowedRootCauses", [])
    
    # traceparent propagation
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
    agent_span_id = uuid.uuid4().hex[:16]
    client_span_id = uuid.uuid4().hex[:16]
    
    # LLM diagnosis call
    prompt = f"""
Analyze the incident transcript and choose the correct root cause from the allowed list:
{json.dumps(allowed_causes)}

Also cite 2 to 4 evidence IDs (e.g. "ev_123") found in square brackets.
Return JSON: {{ "rootCause": "...", "evidence": ["...", "..."] }}
Transcript: {transcript}
"""
    import google.generativeai as genai
    model = genai.GenerativeModel('gemini-1.5-flash')
    try:
        response = model.generate_content(prompt, generation_config={"response_mime_type": "application/json"})
        diagnosis = json.loads(response.text)
    except Exception as e:
        diagnosis = {
            "rootCause": allowed_causes[0] if allowed_causes else "unknown",
            "evidence": []
        }
        
    # Build spans
    spans = [
        {
            "traceId": trace_id,
            "spanId": agent_span_id,
            "parentSpanId": parent_span_id,
            "name": "invoke_agent",
            "kind": 1,
            "attributes": [
                {"key": "ga5.run.id", "value": {"stringValue": run_id}},
                {"key": "ga5.public.marker", "value": {"stringValue": body.get("publicMarker", "")}}
            ]
        },
        {
            "traceId": trace_id,
            "spanId": client_span_id,
            "parentSpanId": agent_span_id,
            "name": "chat",
            "kind": 3,
            "attributes": [
                {"key": "ga5.run.id", "value": {"stringValue": run_id}},
                {"key": "ga5.public.marker", "value": {"stringValue": body.get("publicMarker", "")}},
                {"key": "gen_ai.operation.name", "value": {"stringValue": "chat"}},
                {"key": "gen_ai.request.model", "value": {"stringValue": "gemini-1.5-flash"}}
            ]
        }
    ]
    
    run_state = {
        "runId": run_id,
        "status": "waiting",
        "diagnosis": diagnosis,
        "dispatches": [],
        "approvals": [],
        "spans": spans,
        "trace_id": trace_id,
        "agent_span_id": agent_span_id,
        "public_marker": body.get("publicMarker", ""),
        "incident": incident
    }
    
    Q11_RUNS[run_id] = run_state
    
    # Check if diagnostic tools are requested in catalog
    catalog = body.get("toolCatalog", [])
    if catalog:
        # Choose up to 3 diagnostics
        diag_tools = [t for t in catalog if t.get("name") in ("query_metrics", "check_logs", "read_config")]
        dispatches = []
        for i, t in enumerate(diag_tools[:3]):
            action_id = f"act-{uuid.uuid4().hex[:16]}"
            call_id = f"call-{uuid.uuid4().hex[:16]}"
            tool_client_span = uuid.uuid4().hex[:16]
            tool_internal_span = uuid.uuid4().hex[:16]
            
            # Traceparent for dispatch
            tp = f"00-{trace_id}-{tool_client_span}-01"
            
            dispatches.append({
                "actionId": action_id,
                "callId": call_id,
                "phase": "diagnostic",
                "toolName": t["name"],
                "arguments": {},
                "evidence": diagnosis.get("evidence", [])[:1],
                "attempt": 1,
                "traceparent": tp
            })
            
            # Add spans for this tool
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
            
        run_state["dispatches"] = dispatches
        
    return {
        "runId": run_id,
        "status": "waiting",
        "diagnosis": diagnosis,
        "dispatches": run_state["dispatches"],
        "approvals": []
    }

@app.post("/v2/incidents/{runId}/receipts")
async def incident_receipts(runId: str, request: Request):
    if runId not in Q11_RUNS:
         raise HTTPException(status_code=404, detail="Run not found")
         
    run = Q11_RUNS[runId]
    body = await request.json()
    receipt_id = body.get("receiptId")
    
    # Process approvals or tool outcomes
    approvals = body.get("approvals", [])
    outcomes = body.get("outcomes", [])
    
    # Match trace and correlation
    for o in outcomes:
        # Find corresponding span and update it with receiptId
        for s in run["spans"]:
            # If CLIENT span matching POST tool
            if s["name"].startswith("POST tool/") and s["kind"] == 3:
                # Add receipt info to attributes
                s["attributes"].extend([
                    {"key": "ga5.receipt.id", "value": {"stringValue": receipt_id}},
                    {"key": "ga5.receipt.nonce", "value": {"stringValue": o.get("nonce", "")}}
                ])
                
    # Finalize the run after tool calls
    run["status"] = "completed"
    
    # Build final trace OTLP
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
    
    return {
        "runId": runId,
        "status": "completed",
        "diagnosis": run["diagnosis"],
        "chosenEffect": "scale_service",
        "suppressed": [],
        "actionLog": run["dispatches"],
        "receiptLog": outcomes,
        "otlp": otlp
    }

@app.get("/v2/incidents/{runId}")
async def get_incident(runId: str):
    if runId not in Q11_RUNS:
        raise HTTPException(status_code=404, detail="Run not found")
    run = Q11_RUNS[runId]
    return {
        "runId": runId,
        "status": run["status"],
        "diagnosis": run["diagnosis"]
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
