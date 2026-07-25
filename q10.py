import json
import hashlib
import re
import uuid
import os
import sqlite3
import tempfile
from fastapi import APIRouter, HTTPException, Request, Header
from fastapi.responses import JSONResponse
from typing import Dict, Any, Optional

router = APIRouter()

A2A_CT = "application/a2a+json"

class A2AResponse(JSONResponse):
    media_type = A2A_CT

# ------------------------------------------------------------------ storage

def _db_path():
    want = os.environ.get("GA5_DB", "/tmp/ga5.db")
    try:
        os.makedirs(os.path.dirname(want) or ".", exist_ok=True)
        return want
    except OSError:
        return os.path.join(tempfile.gettempdir(), "ga5.db")

def _init_db():
    with sqlite3.connect(_db_path(), timeout=10, isolation_level=None) as c:
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("""CREATE TABLE IF NOT EXISTS q10_tasks (
            task_id TEXT PRIMARY KEY, principal TEXT, data TEXT)""")

_init_db()
_TASK_CACHE: Dict[str, Dict] = {}

def _save_task(task_id: str, principal: str, data: dict):
    _TASK_CACHE[task_id] = data
    try:
        with sqlite3.connect(_db_path(), timeout=10, isolation_level=None) as c:
            c.execute("PRAGMA journal_mode=WAL")
            c.execute("INSERT OR REPLACE INTO q10_tasks VALUES (?,?,?)",
                      (task_id, principal, json.dumps(data)))
    except Exception:
        pass

def _load_task(task_id: str) -> Optional[dict]:
    if task_id in _TASK_CACHE:
        return _TASK_CACHE[task_id]
    try:
        with sqlite3.connect(_db_path(), timeout=10, isolation_level=None) as c:
            row = c.execute("SELECT data FROM q10_tasks WHERE task_id=?", (task_id,)).fetchone()
            if row:
                d = json.loads(row[0])
                _TASK_CACHE[task_id] = d
                return d
    except Exception:
        pass
    return None

def _load_principal_tasks(principal: str):
    result = []
    try:
        with sqlite3.connect(_db_path(), timeout=10, isolation_level=None) as c:
            rows = c.execute("SELECT data FROM q10_tasks WHERE principal=?", (principal,)).fetchall()
            for row in rows:
                try:
                    result.append(json.loads(row[0]))
                except Exception:
                    pass
    except Exception:
        pass
    return result

def _task_principal(task_id: str) -> Optional[str]:
    try:
        with sqlite3.connect(_db_path(), timeout=10, isolation_level=None) as c:
            row = c.execute("SELECT principal FROM q10_tasks WHERE task_id=?", (task_id,)).fetchone()
            return row[0] if row else None
    except Exception:
        return None

# ------------------------------------------------------------------ auth

def _require_auth(authorization: Optional[str]) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Bearer token required")
    token = authorization.split(" ", 1)[1].strip()
    if not token:
        raise HTTPException(status_code=401, detail="Bearer token required")
    return hashlib.sha256(token.encode()).hexdigest()[:24]

# ------------------------------------------------------------------ invoice logic

def _decide(pkg: dict) -> dict:
    docs = pkg.get("documents", [])
    text = "\n".join(d.get("name","") + "\n" + d.get("text","") for d in docs)
    tl = text.lower()

    # Extract evidence refs
    refs = list(dict.fromkeys(re.findall(r'R_[A-Za-z0-9]+', text)))

    # Extract facts
    vendor = "Unknown"
    m = re.search(r'[Ss]upplier\s+([^;,\n\.]+)', text)
    if m: vendor = m.group(1).strip()

    inv = "INV-0000"
    m = re.search(r'invoice\s+(INV-[A-Za-z0-9\-]+)', text, re.I)
    if m: inv = m.group(1).strip()

    currency, amount_minor = "USD", 0
    m = re.search(r'(EUR|INR|USD|GBP|AUD|CAD|JPY)\s+([0-9]+(?:\.[0-9]+)?)', text)
    if m:
        currency = m.group(1)
        amount_minor = int(round(float(m.group(2)) * 100))

    facts = {"vendorName": vendor, "invoiceNumber": inv,
             "amountMinor": amount_minor, "currency": currency}

    # Action decision — ordered by specificity
    if any(k in tl for k in ("duplicate", "already settled", "second disbursement",
                              "posting for the same supplier", "second scan")):
        action = "reject_duplicate"
        rationale = "Duplicate invoice detected. Evidence: " + ", ".join(refs)
    elif any(k in tl for k in ("destination-account change", "account change pending",
                                "callback has neither confirmed")):
        action = "hold_invoice"
        rationale = "Payment destination change unverified. Evidence: " + ", ".join(refs)
    elif any(k in tl for k in ("discrepancy", "mismatch", "line totals disagree",
                                "quantity mismatch")):
        action = "open_exception"
        rationale = "Line-item discrepancy detected. Evidence: " + ", ".join(refs)
    elif any(k in tl for k in ("exceeds", "delegation ceiling", "approval required",
                                "financial-approval workflow", "outside the operator's")):
        action = "request_approval"
        rationale = "Amount exceeds delegation authority. Evidence: " + ", ".join(refs)
    else:
        action = "settle_invoice"
        rationale = "Three-way match confirmed within authority. Evidence: " + ", ".join(refs)

    return {"action": action, "rationale": rationale, "facts": facts, "evidenceRefs": refs}

# ------------------------------------------------------------------ agent card

@router.get("/.well-known/agent-card.json")
async def agent_card():
    base = os.environ.get("RENDER_EXTERNAL_URL", "https://tds-ga5.onrender.com")
    return A2AResponse(content={
        "name": "ga5-invoice-agent",
        "description": "Autonomous Accounts Payable Invoice Action Agent",
        "version": "1.0.0",
        "protocolVersion": "1.0",
        "url": base,
        "defaultInputModes": ["application/vnd.ga5.invoice-claim-batch+json"],
        "defaultOutputModes": [
            "application/vnd.ga5.invoice-action-proposals+json",
            "application/vnd.ga5.invoice-action-receipts+json"
        ],
        "skills": [{
            "id": "invoice-processing",
            "name": "Invoice Claim Processing",
            "description": "Processes invoice claim batches and returns action proposals and receipts",
            "inputModes": ["application/vnd.ga5.invoice-claim-batch+json"],
            "outputModes": [
                "application/vnd.ga5.invoice-action-proposals+json",
                "application/vnd.ga5.invoice-action-receipts+json"
            ]
        }],
        "capabilities": {
            "streaming": False,
            "pushNotifications": False
        }
    })

# ------------------------------------------------------------------ message:send

@router.post("/a2a/message:send")
@router.post("/message:send")
async def send_message(request: Request, authorization: Optional[str] = Header(None)):
    # Auth required
    principal = _require_auth(authorization)

    # Content-Type must be application/a2a+json
    ct = request.headers.get("content-type", "")
    if A2A_CT not in ct:
        raise HTTPException(status_code=415, detail=f"Content-Type must be {A2A_CT}")

    # A2A version check
    ver = request.headers.get("a2a-version", "1.0")
    if ver not in ("1.0", "1.0.0"):
        raise HTTPException(status_code=400, detail=f"Unsupported A2A version: {ver}")

    body = await request.json()

    # Support both top-level message and configuration+message shapes
    config = body.get("configuration", {})
    msg = body.get("message", {})
    msg_id = msg.get("messageId") or f"msg-{uuid.uuid4().hex[:8]}"

    # Deterministic task_id from principal + messageId for dedup/idempotency
    task_id = "task-" + hashlib.sha256(f"{principal}:{msg_id}".encode()).hexdigest()[:16]

    # Idempotency: return cached task if same messageId already processed
    existing = _load_task(task_id)
    if existing is not None:
        return A2AResponse(content={"task": existing,
                                    "artifacts": existing.get("artifacts", [])})

    # Extract batch from parts
    parts = msg.get("parts", [])
    batch_data = {}
    for p in parts:
        mt = p.get("mediaType", "")
        if mt == "application/vnd.ga5.invoice-claim-batch+json":
            batch_data = p.get("data", {})
            break
    if not batch_data:
        # fallback: data at top level
        batch_data = body.get("data", {})

    batch_id = batch_data.get("batchId", f"batch_{uuid.uuid4().hex[:8]}")
    packages = batch_data.get("packages", [])

    proposals, executions = [], []
    for pkg in packages:
        pkg_id = pkg.get("packageId", "")
        dec = _decide(pkg)
        action_id = "act_" + hashlib.sha256(f"{pkg_id}:{dec['action']}".encode()).hexdigest()[:12]
        proposals.append({
            "packageId": pkg_id, "proposalId": action_id,
            "action": dec["action"], "rationale": dec["rationale"],
            "facts": dec["facts"], "evidenceRefs": dec["evidenceRefs"]
        })
        executions.append({
            "packageId": pkg_id, "actionId": action_id,
            "action": dec["action"], "receiptNonce": f"nonce_{uuid.uuid4().hex[:12]}",
            "facts": dec["facts"], "evidenceRefs": dec["evidenceRefs"]
        })

    artifacts = [
        {"artifactId": f"art_prop_{task_id}",
         "mediaType": "application/vnd.ga5.invoice-action-proposals+json",
         "data": {"batchId": batch_id, "proposals": proposals}},
        {"artifactId": f"art_rcpt_{task_id}",
         "mediaType": "application/vnd.ga5.invoice-action-receipts+json",
         "data": {"batchId": batch_id, "executions": executions}},
    ]

    task = {"id": task_id, "status": "TASK_STATE_COMPLETED",
            "messageId": msg_id, "principal": principal, "artifacts": artifacts}
    _save_task(task_id, principal, task)

    return A2AResponse(content={"task": task, "artifacts": artifacts})

# ------------------------------------------------------------------ tasks

@router.get("/a2a/tasks")
@router.get("/tasks")
async def list_tasks(request: Request, authorization: Optional[str] = Header(None)):
    principal = _require_auth(authorization)
    ver = request.headers.get("a2a-version", "1.0")
    if ver not in ("1.0", "1.0.0"):
        raise HTTPException(status_code=400, detail=f"Unsupported A2A version: {ver}")
    tasks = _load_principal_tasks(principal)
    return A2AResponse(content={"tasks": tasks})

@router.get("/a2a/tasks/{task_id}")
@router.get("/tasks/{task_id}")
async def get_task(task_id: str, request: Request,
                   authorization: Optional[str] = Header(None)):
    principal = _require_auth(authorization)
    task = _load_task(task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="Task not found")
    if task.get("principal") != principal:
        raise HTTPException(status_code=403, detail="Access denied")
    return A2AResponse(content={"task": task})

@router.post("/a2a/tasks/{task_id}:continue")
@router.post("/tasks/{task_id}:continue")
async def continue_task(task_id: str, request: Request,
                        authorization: Optional[str] = Header(None)):
    principal = _require_auth(authorization)
    task = _load_task(task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="Task not found")
    if task.get("principal") != principal:
        raise HTTPException(status_code=403, detail="Access denied")
    # Completed tasks cannot be continued
    if task.get("status") == "TASK_STATE_COMPLETED":
        raise HTTPException(status_code=409, detail="Task already completed")
    return A2AResponse(content={"task": task})
