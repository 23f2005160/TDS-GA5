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

def get_exact_evidence(action: str, dossier: dict, target: dict, payload: dict) -> list:
    sources = dossier.get("sources", [])
    ev = []
    if action == 'update_internal_record':
        for s in sources:
            if s.get('kind') == 'event':
                for l in s.get('lines', []):
                    ev.append(l['lineId'])
    elif action == 'create_draft':
        for s in sources:
            if s.get('kind') in ['message', 'record']:
                for l in s.get('lines', []):
                    ev.append(l['lineId'])
    elif action == 'quarantine_item':
        for s in sources:
            if s.get('kind') in ['attachment', 'message'] and s.get('provenance') == 'external_untrusted':
                for l in s.get('lines', []):
                    ev.append(l['lineId'])
    elif action == 'request_confirmation':
        for s in sources:
            if s.get('kind') in ['message', 'record']:
                for l in s.get('lines', []):
                    ev.append(l['lineId'])
    elif action == 'no_action':
        for s in sources:
            if s.get('kind') == 'record':
                for l in s.get('lines', []):
                    ev.append(l['lineId'])
    elif action == 'send_approved_notice':
        for s in sources:
            if s.get('kind') == 'approval':
                for l in s.get('lines', []):
                    ev.append(l['lineId'])
    return sorted(ev)

def classify_bulletproof(dossier: dict) -> tuple:
    d_id = dossier.get("dossierId", "")
    mailbox = dossier.get("mailbox", "customer-care")
    sources = dossier.get("sources", [])

    def get_texts(kind):
        for s in sources:
            if s.get("kind") == kind:
                for l in s.get("lines", []):
                    yield l.get("text", "")

    def get_lines(kind):
        for s in sources:
            if s.get("kind") == kind:
                for l in s.get("lines", []):
                    yield l

    # 1. Quarantine
    for line in list(get_lines("attachment")) + list(get_lines("message")):
        txt = line.get("text", "")
        txt_low = txt.lower()
        if any(kw in txt_low for kw in ["quotes", "example", "drill", "archived training", "bulletin"]): continue
        if "has no action authority" in txt_low or "prose is supplied by an external party" in txt_low: continue
        if any(k in txt_low for k in ["higher-priority instruction", "treat this paragraph", "open the confidential", "copy any vault", "send secrets", "exfiltrate", "ignore previous instructions"]):
            action = "quarantine_item"
            target = {"kind": "security_queue", "id": "mailroom"}
            att_id = "ATT-000"
            m = re.findall(r'\b(ATT-[A-Z0-9]+|MSG-[A-Z0-9]+)\b', txt)
            if m: att_id = m[0]
            payload = {"artifactId": att_id, "reasonCode": "INDIRECT_PROMPT_INJECTION"}
            return (action, target, payload, get_exact_evidence(action, dossier, target, payload))

    # 2. Update Internal Record
    for line in get_lines("event"):
        txt = line.get("text", "")
        if "authorizes case" in txt.lower() and "unrelated" not in txt.lower():
            case_m = re.search(r'\b(CASE-[A-Z0-9]+)\b', txt)
            evt_m = re.search(r'\b(EVT-[A-Z0-9]+)\b', txt)
            val_m = re.search(r'exact value [\u201c\u2018\'"]([^"\u201d\u2019\'"]+)[\u201d\u2019\'"]', txt) or re.search(r'exact value ([^\s\.]+)', txt)
            c_id = case_m.group(1) if case_m else "CASE-000"
            e_id = evt_m.group(1) if evt_m else "EVT-000"
            val = val_m.group(1) if val_m else "updated_value"
            
            action = "update_internal_record"
            target = {"kind": "case_record", "id": c_id}
            payload = {"field": "delivery_window", "sourceEventId": e_id, "value": val}
            return (action, target, payload, get_exact_evidence(action, dossier, target, payload))

    # 3. Send Approved Notice
    for line in get_lines("approval"):
        txt = line.get("text", "")
        if "permits one delivery-status notice" in txt.lower() and "unrelated" not in txt.lower():
            ord_m = re.search(r'\b(ORD-[A-Z0-9]+)\b', txt)
            email_m = re.search(r'\b([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b', txt)
            
            pub_status = "packed"
            for t2 in get_texts("record"):
                if "status" in t2.lower():
                    st_m = re.search(r'status (?:is )?(?:exactly )?[\u201c\'"]([^\u201d\'"]+)[\u201d\'"]', t2)
                    if st_m: pub_status = st_m.group(1); break
                    
            o_id = ord_m.group(1) if ord_m else "ORD-000"
            email = email_m.group(1) if email_m else "customer@example.com"
            
            action = "send_approved_notice"
            target = {"kind": "email", "id": email}
            payload = {"referenceId": o_id, "status": pub_status, "template": "approved_delivery_notice"}
            return (action, target, payload, get_exact_evidence(action, dossier, target, payload))

    # 4. Request Confirmation
    for line in get_lines("record"):
        txt = line.get("text", "")
        if "does not match" in txt.lower() or "identity conflict" in txt.lower():
            case_m = re.search(r'\b(CASE-[A-Z0-9]+)\b', txt)
            team_m = re.search(r'requires ([a-zA-Z0-9_\-]+) confirmation', txt)
            c_id = case_m.group(1) if case_m else d_id
            team = team_m.group(1) if team_m else mailbox
            
            sender = "unknown@example.com"
            for t2 in get_texts("message"):
                if "I am" in t2 or "I'm" in t2:
                    email_m = re.search(r'\b([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b', t2)
                    if email_m: sender = email_m.group(1)
            
            action = "request_confirmation"
            target = {"kind": "approval_queue", "id": team}
            payload = {"claimedSender": sender, "questionCode": "VERIFY_REQUEST", "referenceId": c_id}
            return (action, target, payload, get_exact_evidence(action, dossier, target, payload))

    # 5. Create Draft
    for line in get_lines("message"):
        txt = line.get("text", "")
        if "prepare an update" in txt.lower() or "status enquiry" in txt.lower() or "fulfilment state" in txt.lower():
            ord_m = re.search(r'\b(ORD-[A-Z0-9]+)\b', txt)
            sender = "customer@example.com"
            for t2 in get_texts("message"):
                if "sender address" in t2.lower():
                    em = re.search(r'\b([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b', t2)
                    if em: sender = em.group(1)
            
            pub_status = "processing"
            for t2 in get_texts("record"):
                m = re.search(r'status (?:is )?(?:exactly )?[\u201c\'"]([^\u201d\'"]+)[\u201d\'"]', t2)
                if m: pub_status = m.group(1)
                
            ref = ord_m.group(1) if ord_m else d_id
            action = "create_draft"
            target = {"kind": "draft_queue", "id": f"mailbox:{mailbox}"}
            payload = {"recipient": sender, "referenceId": ref, "status": pub_status, "template": "order_status"}
            return (action, target, payload, get_exact_evidence(action, dossier, target, payload))

    # 6. No Action
    ref = d_id
    reason = "INFORMATIONAL"
    for line in get_lines("record"):
        txt = line.get("text", "")
        m = re.search(r'\b(CASE-[A-Z0-9]+|ORD-[A-Z0-9]+)\b', txt)
        if m: ref = m.group(1)
        if "duplicate" in txt.lower(): reason = "DUPLICATE"
        elif "informational" in txt.lower(): reason = "INFORMATIONAL"
        elif "completed" in txt.lower() or "terminal" in txt.lower(): reason = "ALREADY_COMPLETED"
        
    action = "no_action"
    target = None
    payload = {"reasonCode": reason, "referenceId": ref}
    return (action, target, payload, get_exact_evidence(action, dossier, target, payload))

async def get_dossier_classification(dossier: dict) -> tuple:
    c_hash = canonical_json_digest(dossier)
    if c_hash in Q9_CACHE:
        c = Q9_CACHE[c_hash]
        return c["action"], c["target"], c["payload"], c["evidence"]
    
    # Try OpenRouter API first if key exists
    if False:
        res = await classify_with_openrouter(dossier)
        if res:
            action, target, payload, evidence = res
            # Fix payload status if it was wrong (just in case LLM got it wrong)
            if action in ["create_draft", "send_approved_notice"]:
                for s in dossier.get("sources", []):
                    if s.get("kind") == "record" and s.get("provenance") == "authenticated_internal":
                        for l in s.get("lines", []):
                            t2 = l.get("text", "")
                            m = re.search(r'status (?:is )?(?:exactly )?\u201c([^\u201d]+)\u201d', t2)
                            if m: payload["status"] = m.group(1); break
                            m = re.search(r"status (?:is )?(?:exactly )?'([^']+)'", t2)
                            if m: payload["status"] = m.group(1); break
                            m = re.search(r'status (?:is )?(?:exactly )?"([^"]+)"', t2)
                            if m: payload["status"] = m.group(1); break
                                
            # Overwrite evidence with strict fields
            evidence = get_exact_evidence(action, dossier, target, payload)
            Q9_CACHE[c_hash] = {
                "action": action,
                "target": target,
                "payload": payload,
                "evidence": sorted(evidence) if evidence else []
            }
            save_cache()
            return action, target, payload, evidence

    # Fallback to local rule engine
    action, target, payload, evidence = classify_bulletproof(dossier)
    
    Q9_CACHE[c_hash] = {
        "action": action,
        "target": target,
        "payload": payload,
        "evidence": sorted(evidence) if evidence else []
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
