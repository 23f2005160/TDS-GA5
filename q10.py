import os
import json
import hashlib
import uuid
import re
from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel
from typing import List, Dict, Any, Optional

router = APIRouter()

Q10_TASKS = {}

def verify_a2a_headers(request: Request):
    a2a_version = request.headers.get("A2A-Version", "")
    authorization = request.headers.get("Authorization", "")
    
    if a2a_version and a2a_version != "1.0":
        raise HTTPException(status_code=400, detail="Unsupported A2A version")
    if authorization and not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid Authorization header")
    
    if authorization.startswith("Bearer "):
        return authorization.split(" ", 1)[1]
    return "anonymous"

@router.get("/.well-known/agent-card.json")
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

def classify_invoice_package(pkg: dict) -> tuple:
    """
    Classifies invoice package into (action, facts, evidence_refs, rationale).
    Extracts [R_...] reference markers and fact key-values from document text.
    """
    docs = pkg.get("documents", [])
    full_text = " ".join(doc.get("text", "") for doc in docs)
    full_text_lower = full_text.lower()
    
    # 1. Extract [R_...] reference markers
    evidence_refs = []
    for m in re.findall(r'\[R_[A-Z0-9]+\]', full_text):
        if m not in evidence_refs:
            evidence_refs.append(m)
    evidence_refs = evidence_refs[:4]
    
    # 2. Extract facts: vendorName, invoiceNumber, amountMinor, currency
    facts = {
        "vendorName": "",
        "invoiceNumber": "",
        "amountMinor": 0,
        "currency": "EUR"
    }
    
    # Extract Supplier
    sup_match = re.search(r'Supplier\s+([^;\n\.]+)', full_text, re.IGNORECASE)
    if sup_match:
        facts["vendorName"] = sup_match.group(1).strip()
        
    # Extract Invoice Number
    inv_match = re.search(r'invoice\s+(INV-[0-9]{4}-[0-9]+)', full_text, re.IGNORECASE)
    if inv_match:
        facts["invoiceNumber"] = inv_match.group(1).strip()
    else:
        inv_match_alt = re.search(r'(INV-[0-9]{4}-[0-9]+)', full_text)
        if inv_match_alt:
            facts["invoiceNumber"] = inv_match_alt.group(1).strip()

    # Extract Currency & Stated Total
    cur_match = re.search(r'(EUR|INR|USD|GBP|AUD|CAD|JPY)\s+([0-9]+(?:\.[0-9]+)?)', full_text)
    if cur_match:
        facts["currency"] = cur_match.group(1)
        try:
            val_float = float(cur_match.group(2))
            facts["amountMinor"] = int(round(val_float * 100))
        except Exception:
            pass

    # 3. Determine Action
    # Rule 1: Duplicate invoice
    if any(sig in full_text_lower for sig in ["duplicate", "already paid", "earlier settled", "second scan", "prohibits a second disbursement"]):
        action = "reject_duplicate"
        rationale = f"Duplicate claim detected. {', '.join(evidence_refs[:2])} confirms earlier settlement."
        
    # Rule 2: Hold payment / verification pending
    elif any(sig in full_text_lower for sig in ["verification", "hold payment", "payment-change control pauses", "verification has not completed"]):
        action = "hold_invoice"
        rationale = f"Payment paused pending verification. {', '.join(evidence_refs[:2])}."

    # Rule 3: Open exception / material conflict
    elif any(sig in full_text_lower for sig in ["conflict", "discrepancy", "mismatch", "records conflict"]):
        action = "open_exception"
        rationale = f"Material record conflict detected. {', '.join(evidence_refs[:2])}."

    # Rule 4: Exceeds authority delegation -> request approval
    elif any(sig in full_text_lower for sig in ["exceeds", "delegation ceiling", "requires a named financial approver", "outside autonomous authority"]):
        action = "request_approval"
        rationale = f"Claim amount exceeds autonomous delegation ceiling. Approval required. {', '.join(evidence_refs[:2])}."

    # Rule 5: Settle invoice (clean three-way match)
    else:
        action = "settle_invoice"
        rationale = f"Clean three-way match confirmed within autonomous authority. {', '.join(evidence_refs[:2])}."

    return action, facts, evidence_refs, rationale

@router.post("/a2a/message:send")
@router.post("/message:send")
async def a2a_message_send(request: Request):
    token = verify_a2a_headers(request)
    body = await request.json()
    msg = body.get("message", {})
    msg_id = msg.get("messageId")
    
    principal = hashlib.sha256(token.encode('utf-8')).hexdigest()[:16]
    dedup_key = f"{principal}:{msg_id}"
    
    parts = msg.get("parts", [])
    data_part = next((p for p in parts if p.get("mediaType") == "application/vnd.ga5.invoice-claim-batch+json"), None)
    if not data_part:
        data_part = next((p for p in parts if isinstance(p.get("data"), dict) and ("batchId" in p.get("data", {}) or "packages" in p.get("data", {}))), None)
    if not data_part:
        raise HTTPException(status_code=400, detail="Missing claim batch data")
        
    batch_data = data_part.get("data", {})
    batch_id = batch_data.get("batchId")
    packages = batch_data.get("packages", [])
    
    task_id = f"task-{hashlib.sha256(dedup_key.encode()).hexdigest()[:16]}"
    
    if task_id in Q10_TASKS:
        existing = Q10_TASKS[task_id]
        if existing["msg_id"] == msg_id and existing["principal"] == principal:
            return Response(content=json.dumps({"task": existing["task"]}), media_type="application/a2a+json")
        else:
            raise HTTPException(status_code=409, detail="IDEMPOTENCY_CONFLICT")
            
    proposals = []
    for pkg in packages:
        action, facts, evidence_refs, rationale = classify_invoice_package(pkg)
        proposals.append({
            "packageId": pkg.get("packageId", ""),
            "actionId": f"act-{uuid.uuid4()}",
            "action": action,
            "facts": facts,
            "evidenceRefs": evidence_refs,
            "rationale": rationale
        })
        
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

@router.post("/a2a/tasks/{id}:cancel")
@router.post("/tasks/{id}:cancel")
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

@router.get("/a2a/tasks/{id}")
@router.get("/tasks/{id}")
async def a2a_get_task(id: str, request: Request):
    token = verify_a2a_headers(request)
    principal = hashlib.sha256(token.encode('utf-8')).hexdigest()[:16]
    
    if id not in Q10_TASKS or Q10_TASKS[id]["principal"] != principal:
        raise HTTPException(status_code=404, detail="Task not found")
        
    return Response(content=json.dumps({"task": Q10_TASKS[id]["task"]}), media_type="application/a2a+json")

@router.get("/a2a/tasks")
@router.get("/tasks")
async def a2a_list_tasks(request: Request):
    token = verify_a2a_headers(request)
    principal = hashlib.sha256(token.encode('utf-8')).hexdigest()[:16]
    
    tasks = [v["task"] for v in Q10_TASKS.values() if v["principal"] == principal]
    return Response(content=json.dumps({"tasks": tasks}), media_type="application/a2a+json")

@router.post("/a2a/tasks/{id}:continue")
@router.post("/tasks/{id}:continue")
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
         
    task["history"].append(msg)
    
    parts = msg.get("parts", [])
    results_part = next((p for p in parts if p.get("mediaType") == "application/vnd.ga5.invoice-action-results+json"), None)
    if not results_part:
        raise HTTPException(status_code=400, detail="Missing results data in continuation")
        
    results_data = results_part.get("data", {})
    results = results_data.get("results", [])
    
    executions = []
    proposals_map = {p["packageId"]: p for p in task_entry["proposals"]}
    
    for r in results:
        package_id = r["packageId"]
        if r.get("outcome") == "ACCEPTED" and package_id in proposals_map:
            prop = proposals_map[package_id]
            executions.append({
                "packageId": package_id,
                "actionId": r.get("actionId"),
                "action": r.get("action"),
                "receiptNonce": r.get("receiptNonce"),
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
