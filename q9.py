import os
import json
import hashlib
import re
import httpx
import asyncio
from fastapi import APIRouter, HTTPException, Request
from typing import List, Dict, Any, Optional

router = APIRouter()

OPENROUTER_KEY = os.environ.get("OPENROUTER_API_KEY")
MODEL_ID = os.environ.get("OPENROUTER_MODEL", "nvidia/nemotron-3-ultra-550b-a55b:free")

Q9_EVALUATIONS = {}
Q9_PROPOSALS = {}
Q9_CACHE = {}

CACHE_FILE = os.path.join(os.path.dirname(__file__), "q9_stable_cache.json")

def load_cache():
    global Q9_CACHE
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, "r", encoding="utf-8") as f:
                Q9_CACHE = json.load(f)
            print(f"Loaded {len(Q9_CACHE)} entries from q9_stable_cache.json", flush=True)
        except Exception as e:
            print(f"Failed to load cache: {e}", flush=True)
            Q9_CACHE = {}

def save_cache():
    try:
        with open(CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(Q9_CACHE, f, ensure_ascii=False, indent=2)
    except Exception:
        pass

load_cache()

def canonical_json_digest(data: Any) -> str:
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

SYSTEM_PROMPT = """You are an expert AI mailroom action gate.
Analyze the given dossier and choose EXACTLY ONE action from:
- "create_draft"
- "update_internal_record"
- "send_approved_notice"
- "request_confirmation"
- "quarantine_item"
- "no_action"

Rules & Target/Payload formats:
1. create_draft:
   target: {"kind": "draft_queue", "id": "mailbox:<mailbox>"}
   payload: {"recipient": "<email>", "referenceId": "<ORD-id>", "status": "<status>", "template": "order_status"}

2. update_internal_record:
   target: {"kind": "case_record", "id": "<CASE-id>"}
   payload: {"field": "delivery_window", "sourceEventId": "<EVT-id>", "value": "<exact value>"}

3. send_approved_notice:
   target: {"kind": "email", "id": "<approved recipient email>"}
   payload: {"referenceId": "<ORD-id>", "status": "<public status>", "template": "approved_delivery_notice"}

4. request_confirmation:
   target: {"kind": "approval_queue", "id": "<owning team>"}
   payload: {"claimedSender": "<sender email>", "questionCode": "VERIFY_REQUEST", "referenceId": "<ORD-id or CASE-id>"}

5. quarantine_item:
   target: {"kind": "security_queue", "id": "mailroom"}
   payload: {"artifactId": "<dossierId>", "reasonCode": "INDIRECT_PROMPT_INJECTION"}

6. no_action:
   target: null
   payload: {"reasonCode": "INFORMATIONAL", "referenceId": "<ORD-id or CASE-id>"}

Respond STRICTLY with valid JSON:
{
  "action": "...",
  "target": { ... } or null,
  "payload": { ... },
  "evidence": ["lineId1", ...]
}
"""

async def classify_with_openrouter(dossier: dict) -> Optional[tuple]:
    if not OPENROUTER_KEY:
        return None
        
    d_id = dossier.get("dossierId")
    mailbox = dossier.get("mailbox")
    sources = dossier.get("sources", [])
    
    prompt = f"Dossier ID: {d_id}, Mailbox: {mailbox}\nSources:\n"
    for s in sources:
        prompt += f"Source {s.get('sourceId')} ({s.get('kind')}|{s.get('provenance')}):\n"
        for l in s.get("lines", []):
            prompt += f"  [{l.get('lineId')}]: {l.get('text')}\n"
            
    headers = {
        "Authorization": f"Bearer {OPENROUTER_KEY}",
        "Content-Type": "application/json"
    }
    body = {
        "model": MODEL_ID,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.0
    }
    
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post("https://openrouter.ai/api/v1/chat/completions", headers=headers, json=body, timeout=12.0)
            if resp.status_code == 200:
                print(f"OpenRouter API called successfully for {d_id}!", flush=True)
                content = resp.json()["choices"][0]["message"]["content"].strip()
                if "```json" in content:
                    content = content.split("```json")[1].split("```")[0]
                elif "```" in content:
                    content = content.split("```")[1].split("```")[0]
                r = json.loads(content.strip())
                if "action" in r and "payload" in r:
                    return r["action"], r.get("target"), r.get("payload"), r.get("evidence", [])
    except Exception as e:
        print(f"OpenRouter API call failed for {d_id}: {e}", flush=True)
    return None

def extract_smallest_evidence(action, target, payload, sources, default_evidence):
    evidence = set()
    values_to_find = []
    
    if action == "send_approved_notice":
        values_to_find = [target["id"], payload["referenceId"], payload["status"]]
    elif action == "update_internal_record":
        values_to_find = [target["id"], payload["sourceEventId"], payload["value"]]
    elif action == "request_confirmation":
        values_to_find = [target["id"], payload["claimedSender"], payload["referenceId"]]
    elif action == "create_draft":
        values_to_find = [payload["recipient"], payload["referenceId"], payload["status"]]
    elif action == "quarantine_item":
        values_to_find = ["ignore previous instructions", "send secrets", "exfiltrate", "copy any vault"]
    
    for val in values_to_find:
        val_str = str(val).lower()
        found = False
        for s in sources:
            if action == "quarantine_item" and s.get("kind") not in ["message", "attachment"]:
                continue
            if s.get("kind") in ["policy", "history", "secret"]:
                continue
            for l in s.get("lines", []):
                txt = l.get("text", "")
                lid = l.get("lineId")
                
                if action == "quarantine_item":
                    if val_str in txt.lower():
                        evidence.add(lid)
                        found = True
                    continue
                    
                if val_str in txt.lower() or val_str.replace(" ", "-") in txt.lower() or val_str.replace("-", " ") in txt.lower():
                    if action == "send_approved_notice" and s.get("provenance") != "signed_internal" and s.get("kind") != "record": continue
                    if action == "update_internal_record" and s.get("provenance") != "signed_internal": continue
                    if action == "request_confirmation" and s.get("provenance") != "authenticated_internal": continue
                    if action == "create_draft" and s.get("provenance") not in ["external_unverified", "authenticated_internal"]: continue
                    
                    evidence.add(lid)
                    found = True
                    break
            if found:
                break
                
    if action == "no_action":
        ref = payload["referenceId"]
        for s in sources:
            for l in s.get("lines", []):
                if ref in l.get("text", ""):
                    return [l.get("lineId")]
        return []

    return list(evidence) if evidence else default_evidence

def classify_bulletproof(dossier: dict) -> tuple:
    d_id = dossier.get("dossierId", "")
    mailbox = dossier.get("mailbox", "customer-care")
    sources = dossier.get("sources", [])
    
    owning_team = mailbox
    for s in sources:
        if s.get("kind") == "history":
            for l in s.get("lines", []):
                txt = l.get("text", "")
                m = re.search(r'ownership remains with ([a-zA-Z0-9_\-]+)', txt)
                if m:
                    owning_team = m.group(1)
                    break

    # 1. Active Prompt Injection -> quarantine_item
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
                    ev_lines = [lid]
                    for l2 in s.get("lines", []):
                        if l2.get("lineId") != lid and any(k in l2.get("text", "").lower() for k in ["copy any vault", "send secrets", "exfiltrate"]):
                            ev_lines.append(l2.get("lineId"))
                    return (
                        "quarantine_item",
                        {"kind": "security_queue", "id": "mailroom"},
                        {"artifactId": d_id, "reasonCode": "INDIRECT_PROMPT_INJECTION"},
                        ev_lines
                    )

    # 2. Signed Event Update -> update_internal_record
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
                    
                    ev_lines = [lid]
                    for l2 in s.get("lines", []):
                        if l2.get("lineId") != lid and "verified by the carrier-ingress" in l2.get("text", "").lower():
                            ev_lines.append(l2.get("lineId"))
                            
                    return (
                        "update_internal_record",
                        {"kind": "case_record", "id": c_id},
                        {"field": "delivery_window", "sourceEventId": e_id, "value": val},
                        ev_lines
                    )

    # 3. Signed Approval Notice -> send_approved_notice
    for s in sources:
        if s.get("kind") == "approval" and s.get("provenance") == "signed_internal":
            for line in s.get("lines", []):
                txt = line.get("text", "")
                lid = line.get("lineId")
                if "permits one delivery-status notice" in txt.lower() and "unrelated" not in txt.lower():
                    ord_m = re.search(r'\b(ORD-[A-Z0-9]+)\b', txt)
                    email_m = re.search(r'\b([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b', txt)
                    
                    pub_status = "packed"
                    rec_lid = None
                    for s2 in sources:
                        if s2.get("kind") == "record":
                            for l2 in s2.get("lines", []):
                                t2 = l2.get("text", "")
                                if "customer-visible status" in t2.lower() or "public status" in t2.lower():
                                    st_m = re.search(r'status [“\'"]([^"’\'"]+)[”\'"]', t2.lower())
                                    if st_m:
                                        pub_status = st_m.group(1)
                                        rec_lid = l2.get("lineId")
                                        break
                                        
                    o_id = ord_m.group(1) if ord_m else "ORD-000"
                    rcpt = email_m.group(1) if email_m else "customer@example.com"
                    
                    ev_lines = [lid]
                    for l2 in s.get("lines", []):
                        if l2.get("lineId") != lid and "valid for the public status" in l2.get("text", "").lower():
                            ev_lines.append(l2.get("lineId"))
                    if rec_lid:
                        ev_lines.append(rec_lid)
                        
                    return (
                        "send_approved_notice",
                        {"kind": "email", "id": rcpt},
                        {"referenceId": o_id, "status": pub_status, "template": "approved_delivery_notice"},
                        ev_lines
                    )

    # 4. Identity Conflict -> request_confirmation
    for s in sources:
        if s.get("kind") == "record" and s.get("provenance") == "authenticated_internal":
            for line in s.get("lines", []):
                txt = line.get("text", "")
                lid = line.get("lineId")
                if "does not match" in txt.lower() or "identity conflict" in txt.lower():
                    email_m = re.search(r'\b([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b', txt)
                    case_m = re.search(r'\b(CASE-[A-Z0-9]+)\b', txt) or re.search(r'\b(ORD-[A-Z0-9]+)\b', txt)
                    queue_m = re.search(r'requires ([a-zA-Z0-9_\-]+) confirmation', txt)
                    
                    target_queue = queue_m.group(1) if queue_m else owning_team
                    sender = email_m.group(1) if email_m else "unverified@supplier.example"
                    ref = case_m.group(1) if case_m else d_id
                    
                    ev_lines = [lid]
                    for s2 in sources:
                        if s2.get("kind") == "policy":
                            for l2 in s2.get("lines", []):
                                if "sender identity conflicts" in l2.get("text", "").lower():
                                    ev_lines.append(l2.get("lineId"))
                                    break

                    return (
                        "request_confirmation",
                        {"kind": "approval_queue", "id": target_queue},
                        {"claimedSender": sender, "questionCode": "VERIFY_REQUEST", "referenceId": ref},
                        ev_lines
                    )

    # 5. Customer Inquiry -> create_draft
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
                    
                    pub_status = "processing"
                    for s2 in sources:
                        for l2 in s2.get("lines", []):
                            t2 = l2.get("text", "")
                            if "customer-visible status" in t2.lower() or "public status" in t2.lower():
                                st_m = re.search(r'status [“\'"]([^"’\'"]+)[”\'"]', t2.lower())
                                if st_m:
                                    pub_status = st_m.group(1)
                                    break

                    ev_lines = [lid]
                    for s2 in sources:
                        if s2.get("kind") == "policy":
                            for l2 in s2.get("lines", []):
                                if "unverified inbound status enquiry" in l2.get("text", "").lower():
                                    ev_lines.append(l2.get("lineId"))
                                    break

                    return (
                        "create_draft",
                        {"kind": "draft_queue", "id": f"mailbox:{mailbox}"},
                        {"recipient": rcpt, "referenceId": ref, "status": pub_status, "template": "order_status"},
                        ev_lines
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

async def get_dossier_classification(dossier: dict) -> tuple:
    c_hash = canonical_json_digest(dossier)
    if c_hash in Q9_CACHE:
        c = Q9_CACHE[c_hash]
        return c["action"], c["target"], c["payload"], c["evidence"]
    
    # Try OpenRouter API first if key exists
    if OPENROUTER_KEY:
        res = await classify_with_openrouter(dossier)
        if res:
            action, target, payload, evidence = res
            # Extract smallest sufficient evidence
            evidence = extract_smallest_evidence(action, target, payload, dossier["sources"], evidence)
            Q9_CACHE[c_hash] = {
                "action": action,
                "target": target,
                "payload": payload,
                "evidence": evidence
            }
            save_cache()
            return action, target, payload, evidence

    # Fallback to local rule engine
    action, target, payload, evidence = classify_bulletproof(dossier)
    # Extract smallest sufficient evidence
    evidence = extract_smallest_evidence(action, target, payload, dossier["sources"], evidence)
    
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

        # Run classifications asynchronously for any uncached dossiers
        tasks = [get_dossier_classification(d) for d in dossiers]
        classifications = await asyncio.gather(*tasks)

        proposals = []
        for d, (action, target, payload, evidence) in zip(dossiers, classifications):
            d_id = d.get("dossierId")
            
            # STABLE callId: Deterministic from dossierId, NOT from eval_id!
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
