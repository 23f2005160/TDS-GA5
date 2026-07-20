import os
import json
import hashlib
import re
import urllib.parse
from fastapi import APIRouter, HTTPException, Request
from typing import List, Dict, Any, Optional

router = APIRouter()

Q9_EVALUATIONS = {}
Q9_PROPOSALS = {}

def canonical_json_digest(data: Any) -> str:
    """Computes SHA-256 hex digest over recursively key-sorted compact JSON."""
    def sort_obj(obj):
        if isinstance(obj, dict):
            return {k: sort_obj(v) for k, v in sorted(obj.items())}
        elif isinstance(obj, list):
            return [sort_obj(x) for x in obj]
        return obj
    
    sorted_data = sort_obj(data)
    compact_json = json.dumps(sorted_data, separators=(',', ':'), ensure_ascii=False)
    return hashlib.sha256(compact_json.encode('utf-8')).hexdigest()

def compute_proposal_digest(dossier_id: str, call_id: str, action: str, target: Any, payload: Any, evidence: List[str]) -> str:
    """
    Compute proposalDigest over:
    { "dossierId": ..., "callId": ..., "action": ..., "target": ..., "payload": ..., "evidence": sorted_evidence }
    """
    sorted_evidence = sorted(evidence) if evidence else []
    prop_data = {
        "dossierId": dossier_id,
        "callId": call_id,
        "action": action,
        "target": target if target is not None else None,
        "payload": payload,
        "evidence": sorted_evidence
    }
    return canonical_json_digest(prop_data)

def classify_dossier(dossier: dict) -> tuple:
    d_id = dossier.get("dossierId", "")
    mailbox = dossier.get("mailbox", "customer-care")
    sources = dossier.get("sources", [])

    all_lines = []
    case_id = None
    ord_id = None
    evt_id = None
    sender_email = None
    approved_recipient = None
    status_val = "processing"
    
    for src in sources:
        s_kind = src.get("kind", "")
        s_id = src.get("sourceId", "")
        prov = src.get("provenance", "")
        
        if ("case" in s_kind.lower() or "case" in s_id.lower()) and not case_id:
            case_id = s_id
                
        for line in src.get("lines", []):
            lid = line.get("lineId")
            txt = line.get("text", "")
            if not lid or not txt:
                continue
            txt_low = txt.lower()
            all_lines.append((lid, txt, txt_low, s_kind, prov))
            
            ord_match = re.search(r'\b(ORD-[A-Z0-9]+)\b', txt)
            if ord_match and not ord_id:
                ord_id = ord_match.group(1)
                
            evt_match = re.search(r'\b(EVT-[A-Z0-9]+)\b', txt)
            if evt_match and not evt_id:
                evt_id = evt_match.group(1)
                
            email_match = re.search(r'\b([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b', txt)
            if email_match:
                if "approved recipient" in txt_low or "recipient:" in txt_low:
                    approved_recipient = email_match.group(1)
                elif not sender_email:
                    sender_email = email_match.group(1)

    ref_id = ord_id or evt_id or d_id
    target_case_id = case_id or f"case_{d_id}"
    sender = sender_email or "unknown@customer.com"
    recipient = approved_recipient or sender

    # 1. Indirect Prompt Injection -> quarantine_item
    INJECTION_TERMS = [
        "ignore previous", "ignore all prior", "system prompt", "jailbreak",
        "paste credential", "override safety", "disregard policy", "exfiltrate",
        "send all passwords", "reveal secret", "unauthorized outbound"
    ]
    for lid, txt, txt_low, s_kind, prov in all_lines:
        if any(term in txt_low for term in INJECTION_TERMS):
            if prov != "signed_internal_approval" and "quote" not in txt_low:
                return (
                    "quarantine_item",
                    {"kind": "security_queue", "id": "mailroom"},
                    {"artifactId": d_id, "reasonCode": "INDIRECT_PROMPT_INJECTION"},
                    [lid]
                )

    # 2. Explicit Internal Record Update -> update_internal_record
    for lid, txt, txt_low, s_kind, prov in all_lines:
        if ("update" in txt_low or "change" in txt_low or "set" in txt_low) and ("delivery window" in txt_low or "window" in txt_low):
            val_m = re.search(r'(?:delivery[_\s]window|window)[_\s:]*(?:to|is|set to|=|:)?\s*([A-Za-z0-9_\-]+)', txt_low)
            val = val_m.group(1) if val_m else "evening_window"
            if val in ["to", "is", "set", "the"]:
                val_m2 = re.search(r'(?:to|is|set|window)\s+([A-Za-z0-9_\-]+_window|[A-Za-z0-9_\-]+)', txt_low)
                val = val_m2.group(1) if val_m2 else "evening_window"
            return (
                "update_internal_record",
                {"kind": "case_record", "id": target_case_id},
                {"field": "delivery_window", "sourceEventId": evt_id or f"EVT_{d_id}", "value": val},
                [lid]
            )

    # 3. Approved Outbound Notice -> send_approved_notice
    for lid, txt, txt_low, s_kind, prov in all_lines:
        if prov == "signed_internal_approval" or "approved delivery notice" in txt_low or "send notice" in txt_low:
            return (
                "send_approved_notice",
                {"kind": "email", "id": recipient},
                {"referenceId": ref_id, "status": "shipped", "template": "approved_delivery_notice"},
                [lid]
            )

    # 4. Identity Conflict / Ambiguous Sender -> request_confirmation
    for lid, txt, txt_low, s_kind, prov in all_lines:
        if "identity conflict" in txt_low or "unverified sender" in txt_low or "mismatch" in txt_low or "ambiguous" in txt_low:
            return (
                "request_confirmation",
                {"kind": "approval_queue", "id": mailbox},
                {"claimedSender": sender, "questionCode": "VERIFY_REQUEST", "referenceId": ref_id},
                [lid]
            )

    # 5. Customer Query needing Draft -> create_draft
    for lid, txt, txt_low, s_kind, prov in all_lines:
        if "customer" in s_kind.lower() or "inquiry" in txt_low or "where is my order" in txt_low or "status request" in txt_low:
            return (
                "create_draft",
                {"kind": "draft_queue", "id": f"mailbox:{mailbox}"},
                {"recipient": sender, "referenceId": ref_id, "status": status_val, "template": "order_status"},
                [lid]
            )

    # 6. Default / Fallback -> no_action
    evidence_line = [all_lines[0][0]] if all_lines else []
    return (
        "no_action",
        None,
        {"reasonCode": "INFORMATIONAL", "referenceId": ref_id},
        evidence_line
    )

@router.post("/v1/mailroom/actions")
async def handle_mailroom_actions(request: Request):
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    profile = body.get("profile")
    operation = body.get("operation")
    eval_id = body.get("evaluationId")

    if profile != "ga5-mailroom-action-gate/v2" or not eval_id or not operation:
        raise HTTPException(status_code=400, detail="Malformed request headers or profile")

    if operation == "propose":
        dossiers = body.get("dossiers", [])
        if not dossiers:
            raise HTTPException(status_code=400, detail="No dossiers provided")

        input_digest = canonical_json_digest(dossiers)

        # Idempotency & Conflict Handling
        if eval_id in Q9_EVALUATIONS:
            cached_eval = Q9_EVALUATIONS[eval_id]
            if cached_eval["inputDigest"] != input_digest:
                raise HTTPException(status_code=409, detail="Evaluation ID conflict with different input digest")
            return cached_eval["proposeResponse"]

        proposals = []
        for d in dossiers:
            d_id = d.get("dossierId")
            action, target, payload, evidence = classify_dossier(d)
            call_id = f"call-{hashlib.sha256(f'{eval_id}:{d_id}'.encode()).hexdigest()[:20]}"
            
            prop_digest = compute_proposal_digest(d_id, call_id, action, target, payload, evidence)
            
            proposal_obj = {
                "dossierId": d_id,
                "callId": call_id,
                "action": action,
                "target": target,
                "payload": payload,
                "evidence": sorted(evidence) if evidence else []
            }
            proposals.append(proposal_obj)
            
            Q9_PROPOSALS[(eval_id, d_id, call_id)] = {
                "proposalDigest": prop_digest,
                "action": action,
                "target": target,
                "payload": payload,
                "evidence": sorted(evidence) if evidence else []
            }

        response_body = {
            "profile": "ga5-mailroom-action-gate/v2",
            "evaluationId": eval_id,
            "status": "awaiting_receipts",
            "inputDigest": input_digest,
            "proposals": proposals
        }

        Q9_EVALUATIONS[eval_id] = {
            "inputDigest": input_digest,
            "proposeResponse": response_body
        }

        return response_body

    elif operation == "commit":
        input_digest = body.get("inputDigest")
        receipts = body.get("receipts", [])

        if eval_id not in Q9_EVALUATIONS:
            raise HTTPException(status_code=400, detail="Unknown evaluationId for commit")

        cached_eval = Q9_EVALUATIONS[eval_id]
        if cached_eval["inputDigest"] != input_digest:
            raise HTTPException(status_code=409, detail="Commit inputDigest mismatch")

        outcomes = []
        for r in receipts:
            d_id = r.get("dossierId")
            c_id = r.get("callId")
            action = r.get("action")
            accepted = r.get("accepted", False)
            prop_digest = r.get("proposalDigest")
            receipt_id = r.get("receiptId")

            key = (eval_id, d_id, c_id)
            if key not in Q9_PROPOSALS:
                status = "rejected"
            else:
                stored = Q9_PROPOSALS[key]
                if stored["proposalDigest"] != prop_digest or stored["action"] != action:
                    status = "rejected"
                else:
                    status = "executed" if accepted else "rejected"

            outcomes.append({
                "dossierId": d_id,
                "callId": c_id,
                "action": action,
                "proposalDigest": prop_digest,
                "receiptId": receipt_id,
                "status": status
            })

        return {
            "profile": "ga5-mailroom-action-gate/v2",
            "evaluationId": eval_id,
            "status": "completed",
            "inputDigest": input_digest,
            "outcomes": outcomes
        }

    else:
        raise HTTPException(status_code=400, detail=f"Invalid operation: {operation}")
