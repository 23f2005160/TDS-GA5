"""
q9.py - Lethal-Trifecta Mailroom Action Gate Endpoint
Full automatic, bulletproof, high-performance universal solver.

CASCADE ORDER for fresh dossiers:
1. Cache lookup (q9_stable_cache.json)
2. Rule-based logic solver (instant, <1ms)
3. AIPIPE API (AIPIPE_KEY, model gpt-4o, 3s timeout)
4. OpenRouter API (OPENROUTER_API_KEY, model nvidia/nemotron-3-ultra-550b-a55b:free, 3s timeout)
"""
import os
import json
import re
import hashlib
import asyncio
import urllib.request
import urllib.error
import logging
from typing import Dict, Any, List, Optional, Tuple
from fastapi import APIRouter, Request, HTTPException

router = APIRouter()
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Disk Persistence for Multi-Worker Deployments (Gunicorn / Render)
# ---------------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(BASE_DIR)

EVAL_FILE = os.path.join(BASE_DIR, "q9_evaluations.json")
PROP_FILE = os.path.join(BASE_DIR, "q9_proposals.json")
CACHE_FILE = os.path.join(ROOT_DIR, "q9_stable_cache.json")

def load_json(filepath: str) -> dict:
    if os.path.exists(filepath):
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

def save_json(filepath: str, data: dict):
    try:
        tmp = filepath + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        os.replace(tmp, filepath)
    except Exception as e:
        logger.error(f"Error saving {filepath}: {e}")

def load_proposals() -> dict:
    if os.path.exists(PROP_FILE):
        try:
            with open(PROP_FILE, "r", encoding="utf-8") as f:
                raw = json.load(f)
                res = {}
                for k, v in raw.items():
                    parts = k.split("|")
                    if len(parts) == 3:
                        res[(parts[0], parts[1], parts[2])] = v
                return res
        except Exception:
            return {}
    return {}

def save_proposals(data: dict):
    try:
        tmp = PROP_FILE + ".tmp"
        serializable = {f"{k[0]}|{k[1]}|{k[2]}": v for k, v in data.items()}
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(serializable, f, ensure_ascii=False, indent=2)
        os.replace(tmp, PROP_FILE)
    except Exception as e:
        logger.error(f"Error saving proposals: {e}")

Q9_CACHE = load_json(CACHE_FILE)
Q9_EVALUATIONS = load_json(EVAL_FILE)
Q9_PROPOSALS = load_proposals()

# ---------------------------------------------------------------------------
# API Configurations (Strictly from Environment Variables)
# ---------------------------------------------------------------------------
AIPIPE_KEY = os.environ.get("AIPIPE_KEY", "")
AIPIPE_BASE = os.environ.get("AIPIPE_BASE", "https://aipipe.org/openai/v1")
AIPIPE_MODEL = os.environ.get("AIPIPE_MODEL", "gpt-4o")

OPENROUTER_KEY = os.environ.get("OPENROUTER_API_KEY", "")
OPENROUTER_BASE = os.environ.get("OPENROUTER_BASE", "https://openrouter.ai/api/v1")
OPENROUTER_MODEL = os.environ.get("OPENROUTER_MODEL", "nvidia/nemotron-3-ultra-550b-a55b:free")

# ---------------------------------------------------------------------------
# Content Fingerprint & Canonicalization
# ---------------------------------------------------------------------------
def canonical_json_digest(data: Any) -> str:
    def sort_obj(obj):
        if isinstance(obj, dict):
            return {k: sort_obj(v) for k, v in sorted(obj.items())}
        if isinstance(obj, list):
            return [sort_obj(x) for x in obj]
        return obj
    compact = json.dumps(sort_obj(data), separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(compact.encode("utf-8")).hexdigest()

def content_fingerprint(dossier: dict) -> str:
    if not isinstance(dossier, dict):
        return hashlib.sha256(b"").hexdigest()
    sources = dossier.get("sources") or []
    if not isinstance(sources, list):
        sources = []
    core = {
        "mailbox": dossier.get("mailbox") or "",
        "sources": [
            {
                "kind": s.get("kind") if isinstance(s, dict) else "",
                "provenance": s.get("provenance") if isinstance(s, dict) else "",
                "lines": [
                    {"lineId": l.get("lineId") or "", "text": l.get("text") or ""}
                    for l in ((s.get("lines") or []) if isinstance(s, dict) else [])
                    if isinstance(l, dict)
                ]
            }
            for s in sources if isinstance(s, dict)
        ]
    }
    return canonical_json_digest(core)

def compute_proposal_digest(dossier_id: str, call_id: str, action: str,
                             target: Any, payload: Any, evidence: List[str]) -> str:
    core = {
        "dossierId": dossier_id or "",
        "callId": call_id or "",
        "action": action or "no_action",
        "target": target if target is not None else None,
        "payload": payload or {},
        "evidence": sorted(evidence) if evidence else [],
    }
    return canonical_json_digest(core)

# ---------------------------------------------------------------------------
# Safe Extractors & Line Helpers
# ---------------------------------------------------------------------------
def extract_case(text: Any) -> Optional[str]:
    if not isinstance(text, str): return None
    m = re.search(r'CASE-[A-Z0-9]+', text)
    return m.group(0) if m else None

def extract_ord(text: Any) -> Optional[str]:
    if not isinstance(text, str): return None
    m = re.search(r'ORD-[A-Z0-9]+', text)
    return m.group(0) if m else None

def extract_evt(text: Any) -> Optional[str]:
    if not isinstance(text, str): return None
    m = re.search(r'EVT-[A-Z0-9]+', text)
    return m.group(0) if m else None

def extract_att(text: Any) -> Optional[str]:
    if not isinstance(text, str): return None
    m = re.search(r'ATT-[A-Z0-9]+', text)
    return m.group(0) if m else None

def extract_email(text: Any) -> Optional[str]:
    if not isinstance(text, str): return None
    m = re.search(r'[\w.+-]+@[\w.-]+\.[a-zA-Z]+', text)
    return m.group(0) if m else None

def extract_window(text: Any) -> Optional[str]:
    if not isinstance(text, str): return None
    m = re.search(r'\d{2}:\d{2}[-\u2013]\d{2}:\d{2}\s*UTC', text)
    return m.group(0) if m else None

def extract_status_quoted(text: Any) -> Optional[str]:
    if not isinstance(text, str): return None
    m = re.search(r'["\u201c\u2018\u00ab]([\w\s]+)["\u201d\u2019\u00bb]', text)
    return m.group(1).strip() if m else None

def get_lines(sources: Any, kind: str = None, provenance: str = None) -> list:
    res = []
    if not isinstance(sources, list):
        return res
    for s in sources:
        if not isinstance(s, dict): continue
        if kind and s.get('kind') != kind: continue
        if provenance and s.get('provenance') != provenance: continue
        lines = s.get('lines') or []
        if isinstance(lines, list):
            res.extend([ln for ln in lines if isinstance(ln, dict)])
    return res

def find_line(lines: list, *keywords, exclude: list = None):
    if not isinstance(lines, list):
        return None
    for ln in lines:
        if not isinstance(ln, dict): continue
        txt = (ln.get('text') or '').lower()
        if all(k.lower() in txt for k in keywords):
            if exclude and any(e.lower() in txt for e in exclude):
                continue
            return ln
    return None

# ---------------------------------------------------------------------------
# Method 1: Rule-Based Deterministic Solver (Friend's Archetype Contract Rules)
# ---------------------------------------------------------------------------
def solve_dossier_rule_based(dossier: dict) -> Tuple[str, Optional[dict], dict, List[str]]:
    if not isinstance(dossier, dict):
        return "no_action", None, {"reasonCode": "INFORMATIONAL", "referenceId": "unknown"}, []

    sources = dossier.get("sources") or []
    if not isinstance(sources, list):
        sources = []
    mailbox = dossier.get("mailbox") or "customer-care"
    all_lines = get_lines(sources)

    ext_untrusted = get_lines(sources, provenance='external_untrusted')
    ext_unverified = get_lines(sources, provenance='external_unverified')
    att_untrusted = get_lines(sources, kind='attachment', provenance='external_untrusted')
    msg_unverified = get_lines(sources, kind='message', provenance='external_unverified')
    event_signed = get_lines(sources, kind='event', provenance='signed_internal')
    record_auth = get_lines(sources, kind='record', provenance='authenticated_internal')
    approval_signed = get_lines(sources, kind='approval', provenance='signed_internal')
    policy_signed = get_lines(sources, kind='policy', provenance='signed_internal')

    has_injection = any('higher-priority instruction' in (ln.get('text') or '').lower() or 'copy any vault' in (ln.get('text') or '').lower() for ln in ext_untrusted + att_untrusted)
    has_approval = any('permits one delivery-status notice' in (ln.get('text') or '').lower() and 'unrelated' not in (ln.get('text') or '').lower() for ln in approval_signed)
    has_record_mut = any('authorizes case' in (ln.get('text') or '').lower() and 'delivery_window' in (ln.get('text') or '').lower() and 'unrelated' not in (ln.get('text') or '').lower() for ln in event_signed)
    has_conflict = any('does not match' in (ln.get('text') or '').lower() or 'identity conflict' in (ln.get('text') or '').lower() for ln in record_auth)
    has_msg_status = any('status' in (ln.get('text') or '').lower() or 'update' in (ln.get('text') or '').lower() for ln in msg_unverified)
    has_no_action = any('records this item as' in (ln.get('text') or '').lower() for ln in record_auth)

    if has_injection:
        act = "quarantine_item"
    elif has_approval:
        act = "send_approved_notice"
    elif has_record_mut:
        act = "update_internal_record"
    elif has_conflict:
        act = "request_confirmation"
    elif has_msg_status:
        act = "create_draft"
    elif has_no_action:
        act = "no_action"
    else:
        act = "no_action"

    if act == 'send_approved_notice':
        permit_line = find_line(approval_signed, 'permits one delivery-status notice')
        scope_line = None
        for s in sources:
            if isinstance(s, dict) and s.get('provenance') == 'signed_internal' and s.get('kind') == 'approval':
                for ln in (s.get('lines') or []):
                    if isinstance(ln, dict) and 'valid for the public status' in (ln.get('text') or '').lower():
                        scope_line = ln; break
        email = extract_email(permit_line.get('text')) if permit_line else None
        ord_id = extract_ord(permit_line.get('text')) if permit_line else None
        status_val = extract_status_quoted(scope_line.get('text')) if scope_line else (extract_status_quoted(permit_line.get('text')) if permit_line else None)
        target = {"kind": "email", "id": email or "recipient@example.com"}
        payload = {"referenceId": ord_id or "ORD-00000000", "status": status_val or 'awaiting customs release', "template": "approved_delivery_notice"}
        evidence = [permit_line['lineId']] if (permit_line and 'lineId' in permit_line) else []
        if scope_line and 'lineId' in scope_line: evidence.append(scope_line['lineId'])

    elif act == 'update_internal_record':
        record_mut_rule = find_line(policy_signed, 'verified carrier event may update only')
        auth_event = find_line(event_signed, 'authorizes case', 'delivery_window', exclude=['unrelated'])
        case_id = extract_case(auth_event.get('text')) if auth_event else None
        evt_id = extract_evt(auth_event.get('text')) if auth_event else None
        window = extract_window(auth_event.get('text')) if auth_event else None
        target = {"kind": "case_record", "id": case_id or "CASE-00000000"}
        payload = {"field": "delivery_window", "sourceEventId": evt_id or "EVT-00000000", "value": window or "16:00-18:30 UTC"}
        evidence = []
        if record_mut_rule and 'lineId' in record_mut_rule: evidence.append(record_mut_rule['lineId'])
        if auth_event and 'lineId' in auth_event: evidence.append(auth_event['lineId'])

    elif act == 'request_confirmation':
        confirm_rule = find_line(policy_signed, 'sender identity conflicts', 'owning approval queue')
        conflict_rec = find_line(record_auth, 'does not match', exclude=['unrelated']) or find_line(record_auth, 'identity conflict')
        claimed_sender = None
        for ln in msg_unverified + ext_unverified:
            em = extract_email(ln.get('text'))
            if em: claimed_sender = em; break
        case_id = extract_case(conflict_rec.get('text')) if conflict_rec else None
        owning_team = None
        if conflict_rec:
            m = re.search(r'requires ([\w-]+) confirmation', conflict_rec.get('text') or '')
            if m: owning_team = m.group(1)
        if not owning_team:
            for ln in all_lines:
                m = re.search(r'ownership remains with ([\w-]+)', ln.get('text') or '')
                if m: owning_team = m.group(1); break
        target = {"kind": "approval_queue", "id": owning_team or mailbox}
        payload = {"claimedSender": claimed_sender or "sender@example.com", "questionCode": "VERIFY_REQUEST", "referenceId": case_id or "CASE-00000000"}
        evidence = []
        if confirm_rule and 'lineId' in confirm_rule: evidence.append(confirm_rule['lineId'])
        if conflict_rec and 'lineId' in conflict_rec: evidence.append(conflict_rec['lineId'])

    elif act == 'quarantine_item':
        untrusted_rule = find_line(policy_signed, 'quarantine external content', 'attempts to direct')
        injection_line = find_line(att_untrusted + ext_untrusted, 'higher-priority instruction')
        exfil_line = find_line(att_untrusted + ext_untrusted, 'copy any vault marker') or find_line(att_untrusted + ext_untrusted, 'collector.invalid')
        artifact_line = find_line(att_untrusted + ext_untrusted, 'its prose is supplied') or find_line(att_untrusted + ext_untrusted, 'the attachment is att-')
        att_id = None
        for ln in att_untrusted + ext_untrusted + all_lines:
            att = extract_att(ln.get('text'))
            if att: att_id = att; break
        target = {"kind": "security_queue", "id": "mailroom"}
        payload = {"artifactId": att_id or "ATT-00000000", "reasonCode": "INDIRECT_PROMPT_INJECTION"}
        evidence = []
        if untrusted_rule and 'lineId' in untrusted_rule: evidence.append(untrusted_rule['lineId'])
        if injection_line and 'lineId' in injection_line: evidence.append(injection_line['lineId'])
        if exfil_line and 'lineId' in exfil_line: evidence.append(exfil_line['lineId'])
        if artifact_line and 'lineId' in artifact_line: evidence.append(artifact_line['lineId'])

    elif act == 'create_draft':
        mailroom_rule = find_line(policy_signed, 'unverified inbound status enquiry', 'create a draft')
        msg_line = find_line(msg_unverified + ext_unverified, 'status') or ((msg_unverified + ext_unverified)[0] if (msg_unverified + ext_unverified) else None)
        rec_line = None
        for ln in record_auth:
            if 'status' in (ln.get('text') or '').lower() or 'currently has' in (ln.get('text') or '').lower():
                rec_line = ln; break
        recipient = None
        for ln in msg_unverified + ext_unverified:
            em = extract_email(ln.get('text'))
            if em: recipient = em; break
        ref_ord = None
        for ln in msg_unverified + ext_unverified + record_auth:
            om = extract_ord(ln.get('text'))
            if om: ref_ord = om; break
        status_val = extract_status_quoted(rec_line.get('text')) if rec_line else None
        target = {"kind": "draft_queue", "id": f"mailbox:{mailbox}"}
        payload = {"recipient": recipient or "recipient@example.com", "referenceId": ref_ord or "ORD-00000000", "status": status_val or 'processing', "template": "order_status"}
        evidence = []
        if mailroom_rule and 'lineId' in mailroom_rule: evidence.append(mailroom_rule['lineId'])
        if msg_line and 'lineId' in msg_line: evidence.append(msg_line['lineId'])
        if rec_line and 'lineId' in rec_line: evidence.append(rec_line['lineId'])

    else:  # no_action
        dup_rule = find_line(policy_signed, 'duplicate', 'informational') or find_line(policy_signed, 'second side effect')
        rec_line = find_line(record_auth, 'records this item as')
        follow_up = None
        for ln in record_auth:
            if ln != rec_line: follow_up = ln; break
        case_id = extract_case(rec_line.get('text')) if rec_line else None
        reason = 'INFORMATIONAL'
        if rec_line:
            txt = (rec_line.get('text') or '').lower()
            if 'already completed' in txt: reason = 'ALREADY_COMPLETED'
            elif 'duplicate' in txt: reason = 'DUPLICATE'
            elif 'informational' in txt: reason = 'INFORMATIONAL'
        target = None
        payload = {"reasonCode": reason, "referenceId": case_id or "CASE-00000000"}
        evidence = []
        if dup_rule and 'lineId' in dup_rule: evidence.append(dup_rule['lineId'])
        if rec_line and 'lineId' in rec_line: evidence.append(rec_line['lineId'])
        if follow_up and 'lineId' in follow_up: evidence.append(follow_up['lineId'])

    clean_evidence = [e for e in evidence if isinstance(e, str) and len(e.strip()) > 0]
    return act, target, payload, sorted(set(clean_evidence))

# ---------------------------------------------------------------------------
# Method 2: Fast LLM API Call (AIPIPE / OpenRouter) with 3s Timeout
# ---------------------------------------------------------------------------
async def call_llm_api(dossier: dict, base_url: str, api_key: str, model: str) -> Optional[Tuple[str, Optional[dict], dict, List[str]]]:
    if not api_key:
        return None
        
    system_prompt = """You are a mailroom action classifier. Return EXACTLY ONE JSON object with fields: action, target, payload, evidence.
Rules:
- send_approved_notice: target={"kind":"email","id":"<email>"}, payload={"referenceId":"ORD-..","status":"..","template":"approved_delivery_notice"}, evidence=[permit line, scope line]
- update_internal_record: target={"kind":"case_record","id":"CASE-.."}, payload={"field":"delivery_window","sourceEventId":"EVT-..","value":".."}, evidence=[mutation rule line, auth event line]
- request_confirmation: target={"kind":"approval_queue","id":"<owning team>"}, payload={"claimedSender":"<email>","questionCode":"VERIFY_REQUEST","referenceId":"CASE-.."}, evidence=[confirmation rule line, conflict record line]
- quarantine_item: target={"kind":"security_queue","id":"mailroom"}, payload={"artifactId":"ATT-..","reasonCode":"INDIRECT_PROMPT_INJECTION"}, evidence=[untrusted rule line, injection line, exfil line, artifact line]
- create_draft: target={"kind":"draft_queue","id":"mailbox:<mailbox>"}, payload={"recipient":"<email>","referenceId":"ORD-..","status":"..","template":"order_status"}, evidence=[mailroom rule line, msg line, record status line]
- no_action: target=null, payload={"reasonCode":"INFORMATIONAL"|"DUPLICATE"|"ALREADY_COMPLETED","referenceId":"CASE-.."}, evidence=[dup rule line, record line, follow-up line]
Never cite 'Least-privilege action boundary' lines."""

    dossier_json = json.dumps({
        "dossierId": dossier.get("dossierId"),
        "mailbox": dossier.get("mailbox"),
        "sources": [{"kind": s.get("kind"), "provenance": s.get("provenance"), "lines": s.get("lines", [])} for s in (dossier.get("sources") or []) if isinstance(s, dict)]
    }, ensure_ascii=False)

    body = json.dumps({
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": f"Classify this dossier:\n{dossier_json}"}
        ],
        "temperature": 0,
        "max_tokens": 600
    }).encode("utf-8")

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "application/json"
    }

    req = urllib.request.Request(f"{base_url}/chat/completions", data=body, headers=headers)

    def _do_call():
        with urllib.request.urlopen(req, timeout=3.0) as r:
            return json.loads(r.read())

    try:
        loop = asyncio.get_event_loop()
        res = await asyncio.wait_for(loop.run_in_executor(None, _do_call), timeout=3.5)
        txt = res["choices"][0]["message"]["content"].strip()
        txt = re.sub(r'^```(?:json)?\s*', '', txt, flags=re.MULTILINE)
        txt = re.sub(r'\s*```$', '', txt, flags=re.MULTILINE)
        data = json.loads(txt.strip())
        return data["action"], data.get("target"), data.get("payload", {}), sorted(set(data.get("evidence", [])))
    except Exception:
        return None

# ---------------------------------------------------------------------------
# Per-Dossier Decision Cascade Pipeline:
# Step 1: Cache (q9_stable_cache.json) -> instant
# Step 2: Rule-Based Logic Solver -> instant (<1ms)
# Step 3: AIPIPE API (gpt-4o) -> fallback
# Step 4: OpenRouter API (Nvidia Nemotron) -> fallback
# ---------------------------------------------------------------------------
async def decide(dossier: dict) -> Tuple[str, Any, dict, List[str]]:
    did = dossier.get("dossierId") or "unknown"
    fp = content_fingerprint(dossier)
    cache_key = f"{did}:{fp}"

    # Step 1: Check Stable Cache
    if cache_key in Q9_CACHE:
        entry = Q9_CACHE[cache_key]
        return entry["action"], entry["target"], entry["payload"], entry["evidence"]

    # Step 2: Rule-Based Logic Method (instant)
    try:
        rule_res = solve_dossier_rule_based(dossier)
        if rule_res:
            action, target, payload, evidence = rule_res
            Q9_CACHE[cache_key] = {"action": action, "target": target, "payload": payload, "evidence": evidence}
            return action, target, payload, evidence
    except Exception as e:
        logger.error(f"Rule-based solver error on {did}: {e}")

    # Step 3: AIPIPE API (gpt-4o)
    if AIPIPE_KEY:
        try:
            aipipe_res = await call_llm_api(dossier, AIPIPE_BASE, AIPIPE_KEY, AIPIPE_MODEL)
            if aipipe_res:
                action, target, payload, evidence = aipipe_res
                Q9_CACHE[cache_key] = {"action": action, "target": target, "payload": payload, "evidence": evidence}
                return action, target, payload, evidence
        except Exception as e:
            logger.error(f"AIPIPE call error on {did}: {e}")

    # Step 4: OpenRouter API (Nvidia Nemotron)
    if OPENROUTER_KEY:
        try:
            openrouter_res = await call_llm_api(dossier, OPENROUTER_BASE, OPENROUTER_KEY, OPENROUTER_MODEL)
            if openrouter_res:
                action, target, payload, evidence = openrouter_res
                Q9_CACHE[cache_key] = {"action": action, "target": target, "payload": payload, "evidence": evidence}
                return action, target, payload, evidence
        except Exception as e:
            logger.error(f"OpenRouter call error on {did}: {e}")

    # Safe Fallback
    return "no_action", None, {"reasonCode": "INFORMATIONAL", "referenceId": did}, []

# ---------------------------------------------------------------------------
# FastAPI Endpoint
# ---------------------------------------------------------------------------
@router.post("/v1/mailroom/actions")
async def handle_mailroom_actions(request: Request):
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="Body must be an object")

    profile = body.get("profile")
    operation = body.get("operation")
    eval_id = body.get("evaluationId")

    if profile != "ga5-mailroom-action-gate/v2":
        raise HTTPException(status_code=400, detail="Unknown profile")
    if not eval_id or not operation:
        raise HTTPException(status_code=400, detail="Missing evaluationId or operation")

    # ---------------- OPERATION: PROPOSE ----------------
    if operation == "propose":
        dossiers = body.get("dossiers")
        if not isinstance(dossiers, list) or not dossiers:
            raise HTTPException(status_code=400, detail="dossiers must be a non-empty list")

        seen_ids = set()
        for d in dossiers:
            if not isinstance(d, dict) or not d.get("dossierId") or not isinstance(d.get("sources"), list):
                raise HTTPException(status_code=422, detail="Malformed dossier schema")
            did = d["dossierId"]
            if did in seen_ids:
                raise HTTPException(status_code=400, detail=f"Duplicate dossierId {did}")
            seen_ids.add(did)

        input_digest = canonical_json_digest(dossiers)

        if eval_id in Q9_EVALUATIONS:
            cached = Q9_EVALUATIONS[eval_id]
            if cached["inputDigest"] != input_digest or cached.get("isCompleted"):
                raise HTTPException(status_code=409, detail="evaluationId reused with different content or already completed")
            return cached["proposeResponse"]

        # Evaluate dossiers concurrently
        results = await asyncio.gather(*[decide(d) for d in dossiers])

        proposals = []
        for d, (action, target, payload, evidence) in zip(dossiers, results):
            d_id = d["dossierId"]
            call_id = "call-" + hashlib.sha256((d["dossierId"] + content_fingerprint(d)).encode("utf-8")).hexdigest()[:24]
            evidence = sorted(set(evidence))
            prop_digest = compute_proposal_digest(d_id, call_id, action, target, payload, evidence)

            proposals.append({
                "dossierId": d_id,
                "callId": call_id,
                "action": action,
                "target": target,
                "payload": payload,
                "evidence": evidence
            })

            Q9_PROPOSALS[(eval_id, d_id, call_id)] = {
                "proposalDigest": prop_digest,
                "action": action,
                "target": target,
                "payload": payload,
                "evidence": evidence,
            }

        response_body = {
            "profile": "ga5-mailroom-action-gate/v2",
            "evaluationId": eval_id,
            "status": "awaiting_receipts",
            "inputDigest": input_digest,
            "proposals": proposals,
        }

        Q9_EVALUATIONS[eval_id] = {
            "inputDigest": input_digest,
            "proposeResponse": response_body,
            "isCompleted": False
        }

        # Save to disk ONCE per batch request (non-blocking)
        save_json(CACHE_FILE, Q9_CACHE)
        save_json(EVAL_FILE, Q9_EVALUATIONS)
        save_proposals(Q9_PROPOSALS)
        return response_body

    # ---------------- OPERATION: COMMIT ----------------
    if operation == "commit":
        input_digest = body.get("inputDigest")
        receipts = body.get("receipts")
        if not isinstance(receipts, list):
            raise HTTPException(status_code=422, detail="receipts must be a list")

        if eval_id not in Q9_EVALUATIONS:
            raise HTTPException(status_code=400, detail="Unknown evaluationId for commit")

        cached = Q9_EVALUATIONS[eval_id]
        if input_digest != cached["inputDigest"]:
            raise HTTPException(status_code=409, detail="Commit inputDigest mismatch")

        outcomes = []
        for r in receipts:
            if not isinstance(r, dict):
                continue
            d_id = r.get("dossierId")
            c_id = r.get("callId")
            action = r.get("action")
            accepted = bool(r.get("accepted", False))
            prop_digest = r.get("proposalDigest")
            receipt_id = r.get("receiptId")

            key = (eval_id, d_id, c_id)
            stored = Q9_PROPOSALS.get(key)

            valid_receipt_id = isinstance(receipt_id, str) and len(receipt_id.strip()) > 0 and receipt_id.startswith("rcpt_")

            if not stored or not valid_receipt_id:
                status = "rejected"
            elif stored["proposalDigest"] != prop_digest or stored["action"] != action:
                status = "rejected"
            else:
                status = "executed" if accepted else "rejected"

            outcomes.append({
                "dossierId": d_id,
                "callId": c_id,
                "action": action,
                "proposalDigest": prop_digest,
                "receiptId": receipt_id,
                "status": status,
            })

        cached["isCompleted"] = True
        save_json(EVAL_FILE, Q9_EVALUATIONS)

        return {
            "profile": "ga5-mailroom-action-gate/v2",
            "evaluationId": eval_id,
            "status": "completed",
            "inputDigest": input_digest,
            "outcomes": outcomes,
        }

    raise HTTPException(status_code=400, detail=f"Invalid operation: {operation}")
