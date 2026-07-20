import os
import json
import hashlib
import re
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
from llm import call_llm_json

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
    Fast rule-based classifier for Q9 dossiers.
    """
    d_id = dossier.get("dossierId", "")
    mailbox = dossier.get("mailbox", "customer-care")
    sources = dossier.get("sources", [])
    
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
    default_evidence = [lid for lid, _, _ in all_lines[:2]]
    
    # Rule 1: Prompt Injection / Security Threat -> quarantine_item
    INJECTION_KEYWORDS = [
        "indirect_prompt_injection", "prompt injection", "ignore previous",
        "override instruction", "jailbreak", "paste credential",
        "disregard policy", "ignore all", "system prompt", "you are now"
    ]
    if any(kw in full_text for kw in INJECTION_KEYWORDS):
        ev = [lid for lid, _, t_low in all_lines if any(kw in t_low for kw in INJECTION_KEYWORDS)][:2]
        return (
            "quarantine_item",
            {"kind": "security_queue", "id": "mailroom"},
            {"artifactId": d_id, "reasonCode": "INDIRECT_PROMPT_INJECTION"},
            ev or default_evidence
        )

    # Rule 2: Update internal record
    if "delivery_window" in full_text or "delivery window" in full_text or "update_internal_record" in full_text:
        target_case_id = case_record_id or "case-record-0"
        ev = [lid for lid, _, t_low in all_lines if "delivery" in t_low or "update" in t_low][:2]
        val_match = re.search(r'delivery[_\s]window[_\s:]*([A-Za-z0-9_\-]+)', full_text)
        val = val_match.group(1) if val_match else "updated_window"
        return (
            "update_internal_record",
            {"kind": "case_record", "id": target_case_id},
            {"field": "delivery_window", "sourceEventId": d_id, "value": val},
            ev or default_evidence
        )

    # Rule 3: Create draft order status
    if "create_draft" in full_text or "draft order" in full_text or "order_status" in full_text or "draft queue" in full_text:
        ev = [lid for lid, _, t_low in all_lines if "draft" in t_low or "order" in t_low][:2]
        return (
            "create_draft",
            {"kind": "draft_queue", "id": f"mailbox:{mailbox}"},
            {"recipient": mailbox, "referenceId": d_id, "status": "pending", "template": "order_status"},
            ev or default_evidence
        )

    # Rule 4: Send approved notice
    if "approved_delivery_notice" in full_text or "approved notice" in full_text or "send_approved_notice" in full_text:
        ev = [lid for lid, _, t_low in all_lines if "approved" in t_low][:2]
        return (
            "send_approved_notice",
            {"kind": "email", "id": mailbox},
            {"referenceId": d_id, "status": "approved", "template": "approved_delivery_notice"},
            ev or default_evidence
        )

    # Rule 5: Request confirmation
    if "verify_request" in full_text or "request_confirmation" in full_text or "suspicious sender" in full_text or "unverified sender" in full_text:
        ev = [lid for lid, _, t_low in all_lines if "sender" in t_low or "verify" in t_low or "confirm" in t_low][:2]
        return (
            "request_confirmation",
            {"kind": "approval_queue", "id": "compliance-team"},
            {"claimedSender": mailbox, "questionCode": "VERIFY_REQUEST", "referenceId": d_id},
            ev or default_evidence
        )

    # Rule 6: Default -> no_action
    reason = "INFORMATIONAL"
    if "already completed" in full_text or "already processed" in full_text:
        reason = "ALREADY_COMPLETED"
    elif "duplicate" in full_text:
        reason = "DUPLICATE"
        
    return (
        "no_action",
        None,
        {"reasonCode": reason, "referenceId": d_id},
        default_evidence
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
            
            if d_hash in Q9_CACHE:
                prop = Q9_CACHE[d_hash].copy()
                prop["callId"] = call_id
                proposals.append(prop)
            else:
                action, target, payload, evidence = classify_dossier_fast(d)
                prop = {
                    "dossierId": d_id,
                    "callId": call_id,
                    "action": action,
                    "target": target,
                    "payload": payload,
                    "evidence": evidence
                }
                Q9_CACHE[d_hash] = prop
                proposals.append(prop)
                
        save_q9_cache()
        
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
