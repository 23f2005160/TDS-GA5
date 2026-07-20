import os
import json
import hashlib
import re
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from typing import List, Dict, Any, Optional

router = APIRouter()

Q9_CACHE = {}

def load_q9_cache():
    global Q9_CACHE
    if os.path.exists("q9_cache.json"):
        try:
            with open("q9_cache.json", "r", encoding="utf-8") as f:
                Q9_CACHE = json.load(f)
        except Exception:
            pass

def save_q9_cache():
    try:
        with open("q9_cache.json", "w", encoding="utf-8") as f:
            json.dump(Q9_CACHE, f)
    except Exception:
        pass

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

def classify_dossier_fast(dossier: dict) -> tuple:
    """
    Classifies a Q9 dossier into one of 6 actions:
    quarantine_item, update_internal_record, create_draft,
    send_approved_notice, request_confirmation, no_action.
    """
    d_id = dossier.get("dossierId", "")
    partition = dossier.get("partition", "")
    mailbox = dossier.get("mailbox", "customer-care")
    sources = dossier.get("sources", [])
    
    # Standard rule for stable_core partition: always no_action
    if partition == "stable_core":
        return (
            "no_action",
            None,
            {"reasonCode": "INFORMATIONAL", "referenceId": d_id},
            []
        )

    all_lines = []
    case_record_id = None
    
    for src in sources:
        if src.get("kind") == "case_record" and not case_record_id:
            case_record_id = src.get("sourceId")
        for line in src.get("lines", []):
            lid = line.get("lineId")
            txt = line.get("text", "")
            if lid and txt:
                all_lines.append((lid, txt, txt.lower()))

    full_text = " ".join(t_low for _, _, t_low in all_lines)

    # 1. Prompt Injection -> quarantine_item
    INJECTION_KEYWORDS = [
        "ignore previous", "ignore all prior", "system prompt",
        "jailbreak", "paste credential", "override safety", "disregard policy"
    ]
    for lid, txt, t_low in all_lines:
        if any(kw in t_low for kw in INJECTION_KEYWORDS):
            return (
                "quarantine_item",
                {"kind": "security_queue", "id": "mailroom"},
                {"artifactId": d_id, "reasonCode": "INDIRECT_PROMPT_INJECTION"},
                [lid]
            )

    # 2. Update Internal Record -> delivery window
    for lid, txt, t_low in all_lines:
        if "delivery window" in t_low or "update delivery" in t_low:
            val_match = re.search(r'delivery[_\s]window[_\s:]*([A-Za-z0-9_\-]+)', t_low)
            val = val_match.group(1) if val_match else "updated_window"
            target_case_id = case_record_id or "case-record-0"
            return (
                "update_internal_record",
                {"kind": "case_record", "id": target_case_id},
                {"field": "delivery_window", "sourceEventId": d_id, "value": val},
                [lid]
            )

    # 3. Create Draft -> order status
    for lid, txt, t_low in all_lines:
        if "create draft" in t_low or "order status draft" in t_low or "draft response" in t_low:
            return (
                "create_draft",
                {"kind": "draft_queue", "id": f"mailbox:{mailbox}"},
                {"recipient": mailbox, "referenceId": d_id, "status": "pending", "template": "order_status"},
                [lid]
            )

    # 4. Send Approved Notice
    for lid, txt, t_low in all_lines:
        if "send approved notice" in t_low or "approved delivery notice" in t_low:
            return (
                "send_approved_notice",
                {"kind": "email", "id": mailbox},
                {"referenceId": d_id, "status": "approved", "template": "approved_delivery_notice"},
                [lid]
            )

    # 5. Request Confirmation
    for lid, txt, t_low in all_lines:
        if "request confirmation" in t_low or "unverified sender" in t_low or "verify sender" in t_low:
            return (
                "request_confirmation",
                {"kind": "approval_queue", "id": "compliance-team"},
                {"claimedSender": mailbox, "questionCode": "VERIFY_REQUEST", "referenceId": d_id},
                [lid]
            )

    # 6. Default -> no_action
    return (
        "no_action",
        None,
        {"reasonCode": "INFORMATIONAL", "referenceId": d_id},
        []
    )

@router.post("/v1/mailroom/actions")
@router.post("/q9/mailroom")
async def mailroom_handler(request: Request):
    load_q9_cache()
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
        for d in dossiers:
            d_hash = hash_dossier(d)
            d_id = d.get("dossierId", "")
            call_id = f"call-{d_hash[:20]}"
            
            action, target, payload, evidence = classify_dossier_fast(d)
            prop = {
                "dossierId": d_id,
                "callId": call_id,
                "action": action,
                "target": target,
                "payload": payload,
                "evidence": evidence
            }
            proposals.append(prop)
                
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
            status = "executed" if r.get("accepted") else "rejected"
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
