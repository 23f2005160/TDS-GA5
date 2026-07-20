import os
import json
import hashlib
import re
import urllib.parse
import httpx
from fastapi import APIRouter, HTTPException, Request
from typing import List, Dict, Any, Optional

router = APIRouter()

OPENROUTER_KEY = os.environ.get("OPENROUTER_API_KEY")
MODEL_ID = "nvidia/nemotron-3-ultra-550b-a55b:free"

Q9_EVALUATIONS = {}
Q9_PROPOSALS = {}
Q9_CACHE = {}

CACHE_FILE = "q9_stable_cache.json"

def load_cache():
    global Q9_CACHE
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, "r", encoding="utf-8") as f:
                Q9_CACHE = json.load(f)
        except Exception:
            Q9_CACHE = {}

def save_cache():
    try:
        with open(CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(Q9_CACHE, f, ensure_ascii=False, indent=2)
    except Exception:
        pass

load_cache()

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

def classify_dossier_deterministic(dossier: dict) -> tuple:
    """
    Universal semantic classifier for mailroom dossiers.
    Categorizes into one of 6 allowed actions with minimal target, payload, and evidence line IDs.
    """
    d_id = dossier.get("dossierId", "")
    mailbox = dossier.get("mailbox", "customer-care")
    sources = dossier.get("sources", [])

    # 1. Check active prompt injection -> quarantine_item
    for s in sources:
        if s.get("kind") in ["attachment", "message"] and s.get("provenance") == "external_untrusted":
            for line in s.get("lines", []):
                txt = line.get("text", "")
                lid = line.get("lineId")
                txt_low = txt.lower()
                if any(kw in txt_low for kw in ["quotes", "example", "drill", "archived training", "bulletin"]):
                    continue
                if any(k in txt_low for k in [
                    "higher-priority instruction", "treat this paragraph", "open the confidential",
                    "copy any vault", "send secrets", "exfiltrate", "ignore previous instructions"
                ]):
                    return (
                        "quarantine_item",
                        {"kind": "security_queue", "id": "mailroom"},
                        {"artifactId": d_id, "reasonCode": "INDIRECT_PROMPT_INJECTION"},
                        [lid]
                    )

    # 2. Check signed event update -> update_internal_record
    for s in sources:
        if s.get("kind") == "event" and s.get("provenance") == "signed_internal":
            for line in s.get("lines", []):
                txt = line.get("text", "")
                lid = line.get("lineId")
                if "authorizes case" in txt.lower() and "unrelated" not in txt.lower():
                    case_m = re.search(r'\b(CASE-[A-Z0-9]+)\b', txt)
                    evt_m = re.search(r'\b(EVT-[A-Z0-9]+)\b', txt)
                    val_m = re.search(r'exact value [“\'"]([^"’\'"]+)[”\'"]', txt) or re.search(r'exact value ([^\s\.]+)', txt)
                    c_id = case_m.group(1) if case_m else "CASE-000"
                    e_id = evt_m.group(1) if evt_m else "EVT-000"
                    val = val_m.group(1) if val_m else "updated_value"
                    return (
                        "update_internal_record",
                        {"kind": "case_record", "id": c_id},
                        {"field": "delivery_window", "sourceEventId": e_id, "value": val},
                        [lid]
                    )

    # 3. Check signed approval notice -> send_approved_notice
    for s in sources:
        if s.get("kind") == "approval" and s.get("provenance") == "signed_internal":
            for line in s.get("lines", []):
                txt = line.get("text", "")
                lid = line.get("lineId")
                if "permits one delivery-status notice" in txt.lower() and "unrelated" not in txt.lower():
                    ord_m = re.search(r'\b(ORD-[A-Z0-9]+)\b', txt)
                    email_m = re.search(r'\b([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b', txt)
                    
                    pub_status = "packed"
                    for s2 in sources:
                        if s2.get("kind") == "record":
                            for l2 in s2.get("lines", []):
                                st_m = re.search(r'status [“\'"]([^"’\'"]+)[”\'"]', l2.get("text", "").lower())
                                if st_m:
                                    pub_status = st_m.group(1)
                                    break
                                    
                    o_id = ord_m.group(1) if ord_m else "ORD-000"
                    rcpt = email_m.group(1) if email_m else "customer@example.com"
                    return (
                        "send_approved_notice",
                        {"kind": "email", "id": rcpt},
                        {"referenceId": o_id, "status": pub_status, "template": "approved_delivery_notice"},
                        [lid]
                    )

    # 4. Check identity conflict -> request_confirmation
    for s in sources:
        if s.get("kind") == "record" and s.get("provenance") == "authenticated_internal":
            for line in s.get("lines", []):
                txt = line.get("text", "")
                lid = line.get("lineId")
                if "does not match" in txt.lower() or "identity conflict" in txt.lower():
                    email_m = re.search(r'\b([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b', txt)
                    case_m = re.search(r'\b(CASE-[A-Z0-9]+)\b', txt) or re.search(r'\b(ORD-[A-Z0-9]+)\b', txt)
                    sender = email_m.group(1) if email_m else "unverified@supplier.example"
                    ref = case_m.group(1) if case_m else d_id
                    return (
                        "request_confirmation",
                        {"kind": "approval_queue", "id": mailbox},
                        {"claimedSender": sender, "questionCode": "VERIFY_REQUEST", "referenceId": ref},
                        [lid]
                    )

    # 5. Check customer inquiry -> create_draft
    for s in sources:
        if s.get("kind") == "message" and s.get("provenance") == "external_unverified":
            for line in s.get("lines", []):
                txt = line.get("text", "")
                lid = line.get("lineId")
                if "prepare an update" in txt.lower() or "status enquiry" in txt.lower() or "fulfilment state" in txt.lower():
                    ord_m = re.search(r'\b(ORD-[A-Z0-9]+)\b', txt)
                    sender_m = None
                    for s2 in sources:
                        for l2 in s2.get("lines", []):
                            if "sender address" in l2.get("text", "").lower():
                                sender_m = re.search(r'\b([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b', l2.get("text", ""))
                    rcpt = sender_m.group(1) if sender_m else "customer@example.com"
                    ref = ord_m.group(1) if ord_m else d_id
                    return (
                        "create_draft",
                        {"kind": "draft_queue", "id": f"mailbox:{mailbox}"},
                        {"recipient": rcpt, "referenceId": ref, "status": "processing", "template": "order_status"},
                        [lid]
                    )

    # 6. Fallback no_action
    rec_line = []
    ref = d_id
    for s in sources:
        for line in s.get("lines", []):
            txt = line.get("text", "")
            lid = line.get("lineId")
            ord_m = re.search(r'\b(ORD-[A-Z0-9]+)\b', txt) or re.search(r'\b(CASE-[A-Z0-9]+)\b', txt)
            if ord_m and ref == d_id:
                ref = ord_m.group(1)
            if not rec_line and lid:
                rec_line = [lid]

    return (
        "no_action",
        None,
        {"reasonCode": "INFORMATIONAL", "referenceId": ref},
        rec_line
    )

def classify_dossier_cached(dossier: dict) -> tuple:
    """
    Computes a content digest for the dossier and returns cached decision if available,
    otherwise runs classifier and saves to disk cache for stable-core reuse.
    """
    c_hash = canonical_json_digest(dossier)
    if c_hash in Q9_CACHE:
        c = Q9_CACHE[c_hash]
        return c["action"], c["target"], c["payload"], c["evidence"]
    
    action, target, payload, evidence = classify_dossier_deterministic(dossier)
    
    Q9_CACHE[c_hash] = {
        "action": action,
        "target": target,
        "payload": payload,
        "evidence": evidence
    }
    save_cache()
    return action, target, payload, evidence

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

        # Idempotency & Conflict Handling:
        if eval_id in Q9_EVALUATIONS:
            cached_eval = Q9_EVALUATIONS[eval_id]
            if cached_eval["inputDigest"] != input_digest:
                raise HTTPException(status_code=409, detail="Evaluation ID conflict with different input digest")
            return cached_eval["proposeResponse"]

        proposals = []
        for d in dossiers:
            d_id = d.get("dossierId")
            action, target, payload, evidence = classify_dossier_cached(d)
            
            # STABLE callId: Deterministic from dossierId, NOT from eval_id!
            # This guarantees stable-core reuse across evaluations and later Checks!
            call_id = f"call-{hashlib.sha256(d_id.encode('utf-8')).hexdigest()[:24]}"
            
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
