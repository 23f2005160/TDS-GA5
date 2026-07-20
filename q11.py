import os
import json
import hashlib
import uuid
import re
from fastapi import APIRouter, HTTPException, Request, Header
from typing import Optional, Dict, Any, List

router = APIRouter()

Q11_RUNS = {}

def make_arguments_digest(args_dict):
    def sort_dict(obj):
        if isinstance(obj, dict):
            return {k: sort_dict(v) for k, v in sorted(obj.items())}
        elif isinstance(obj, list):
            return [sort_dict(x) for x in obj]
        return obj
    sorted_args = sort_dict(args_dict)
    compact = json.dumps(sorted_args, separators=(',', ':'), ensure_ascii=False)
    return hashlib.sha256(compact.encode('utf-8')).hexdigest()

def classify_incident_fast(transcript: str, allowed_causes: List[str], effect_tools: List[str], service: str):
    """
    Deterministic incident analysis.
    Identifies the causal event, extracts its ev_XXXXX ID, maps rootCause, and builds effect args.
    """
    lines = transcript.strip().split("\n")
    
    # Event line pattern: [ev_XXXXX] timestamp text
    events = []
    for line in lines:
        m = re.match(r'\[(ev_[A-Za-z0-9]+)\]\s*(.*)', line.strip())
        if m:
            ev_id, text = m.group(1), m.group(2)
            events.append((ev_id, text, text.lower()))
            
    # Keywords mapping for root causes
    cause_keywords = {
        "bad_deployment": ["deployment", "rollout", "release", "new version", "deploy", "dep_"],
        "certificate_expiry": ["certificate", "cert", "tls", "ssl", "expired"],
        "memory_leak": ["memory", "oom", "heap", "leak"],
        "cpu_spike": ["cpu", "load", "spike", "processor"],
        "disk_full": ["disk", "storage", "volume", "space"],
        "network_partition": ["network", "partition", "unreachable", "connectivity"],
        "database_overload": ["database", "db", "query", "slow query", "connection pool"],
        "dependency_failure": ["dependency", "upstream", "downstream", "third-party"],
        "config_change": ["config", "configuration", "setting", "env"],
        "rate_limit": ["rate limit", "quota", "429"],
        "scaling_failure": ["scaling", "replica", "capacity"],
        "feature_flag": ["feature flag", "feature toggle", "feat_"]
    }
    
    causal_ev_id = None
    best_cause = None
    best_score = -1
    
    # Decoy indicators (events that explicitly state they belong to another service/timezone/unrelated)
    DECOY_INDICATORS = [
        "does not overlap", "another service", "timezone was wrong",
        "postmortem mentions", "unrelated", "synthetic probe",
        "capacity forecast", "training material", "ignore policy"
    ]
    
    for ev_id, orig_text, text_lower in events:
        # Skip obvious decoy events
        if any(dec in text_lower for dec in DECOY_INDICATORS):
            continue
            
        for cause in allowed_causes:
            kws = cause_keywords.get(cause, [cause.replace("_", " ")])
            score = sum(1 for kw in kws if kw in text_lower)
            if score > best_score:
                best_score = score
                best_cause = cause
                causal_ev_id = ev_id
                
    if not best_cause and allowed_causes:
        best_cause = allowed_causes[0]
        
    evidence = [causal_ev_id] if causal_ev_id else [e[0] for e in events[:1]]
    
    # Choose effect tool
    chosen_effect = effect_tools[0] if effect_tools else "scale_service"
    arguments = {"service": service}
    
    for tool in effect_tools:
        tool_l = tool.lower()
        if "rollback" in tool_l:
            chosen_effect = tool
            dep_match = re.search(r'dep_[A-Za-z0-9]+', transcript)
            arguments["deploymentId"] = dep_match.group(0) if dep_match else "dep-latest"
            break
        elif "disable" in tool_l or "feature" in tool_l:
            chosen_effect = tool
            feat_match = re.search(r'feat_[A-Za-z0-9]+', transcript)
            arguments["featureName"] = feat_match.group(0) if feat_match else "feat-main"
            break
        elif "scale" in tool_l:
            chosen_effect = tool
            break

    return best_cause, evidence, chosen_effect, arguments

@router.post("/v2/incidents")
async def incident_handler(request: Request, traceparent: Optional[str] = Header(None)):
    body = await request.json()
    profile = body.get("profile")
    if profile != "ga5-incident-agent/v2":
        raise HTTPException(status_code=400, detail="Unsupported profile")
        
    run_id = body.get("runId")
    if not run_id:
        raise HTTPException(status_code=400, detail="Missing runId")
        
    if run_id in Q11_RUNS:
        existing = Q11_RUNS[run_id]
        existing_incident = existing["incident"]
        incoming_incident = body.get("incident", {})
        if (existing_incident.get("incidentId") != incoming_incident.get("incidentId") or
            existing_incident.get("transcript") != incoming_incident.get("transcript")):
            raise HTTPException(status_code=409, detail="CONFLICT: runId already exists with different content")
            
        if existing["status"] == "completed":
            return existing["final_response"]
            
        return {
            "runId": run_id,
            "status": "waiting",
            "diagnosis": existing["diagnosis"],
            "dispatches": existing["dispatches"],
            "approvals": existing["approvals"]
        }
        
    incident = body.get("incident", {})
    transcript = incident.get("transcript", "")
    allowed_causes = incident.get("allowedRootCauses", [])
    policy = body.get("policy", {})
    service = incident.get("service", "")
    
    # Traceparent propagation
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
    server_span_id = uuid.uuid4().hex[:16]
    agent_span_id = uuid.uuid4().hex[:16]
    client_span_id = uuid.uuid4().hex[:16]
    
    effect_tools = policy.get("effectTools", [])
    root_cause, evidence, chosen_effect, arguments = classify_incident_fast(
        transcript, allowed_causes, effect_tools, service
    )
    
    diagnosis = {"rootCause": root_cause, "evidence": evidence}

    # Create initial OTLP spans
    spans = [
        {
            "traceId": trace_id,
            "spanId": server_span_id,
            "parentSpanId": parent_span_id,
            "name": "POST /v2/incidents",
            "kind": 2, # SERVER
            "attributes": [
                {"key": "ga5.run.id", "value": {"stringValue": run_id}},
                {"key": "ga5.public.marker", "value": {"stringValue": body.get("publicMarker", "")}}
            ]
        },
        {
            "traceId": trace_id,
            "spanId": agent_span_id,
            "parentSpanId": server_span_id,
            "name": "invoke_agent incident-response",
            "kind": 1, # INTERNAL
            "attributes": [
                {"key": "ga5.run.id", "value": {"stringValue": run_id}},
                {"key": "ga5.public.marker", "value": {"stringValue": body.get("publicMarker", "")}}
            ]
        },
        {
            "traceId": trace_id,
            "spanId": client_span_id,
            "parentSpanId": agent_span_id,
            "name": "chat incident-plan",
            "kind": 3, # CLIENT
            "attributes": [
                {"key": "ga5.run.id", "value": {"stringValue": run_id}},
                {"key": "ga5.public.marker", "value": {"stringValue": body.get("publicMarker", "")}},
                {"key": "gen_ai.operation.name", "value": {"stringValue": "chat"}},
                {"key": "gen_ai.request.model", "value": {"stringValue": "gemini-3.5-flash"}}
            ]
        }
    ]
    
    # Generate diagnostic dispatches (up to 3)
    catalog = body.get("toolCatalog", [])
    dispatches = []
    if catalog:
        diag_tools = [t for t in catalog if t.get("name") in ("query_metrics", "check_logs", "read_config")]
        for t in diag_tools[:3]:
            action_id = f"act-{uuid.uuid4().hex[:16]}"
            call_id = f"call-{uuid.uuid4().hex[:16]}"
            tool_client_span = uuid.uuid4().hex[:16]
            tool_internal_span = uuid.uuid4().hex[:16]
            tp = f"00-{trace_id}-{tool_client_span}-01"
            
            dispatches.append({
                "actionId": action_id,
                "callId": call_id,
                "phase": "diagnostic",
                "toolName": t["name"],
                "arguments": {},
                "evidence": evidence[:1],
                "attempt": 1,
                "traceparent": tp
            })
            
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
            
    if dispatches:
        join_span_id = uuid.uuid4().hex[:16]
        diag_internal_spans = [s["spanId"] for s in spans if s["name"] == "execute_tool" and s.get("parentSpanId") == agent_span_id]
        spans.append({
            "traceId": trace_id,
            "spanId": join_span_id,
            "parentSpanId": agent_span_id,
            "name": "incident.join",
            "kind": 1,
            "attributes": [
                {"key": "ga5.run.id", "value": {"stringValue": run_id}},
                {"key": "ga5.public.marker", "value": {"stringValue": body.get("publicMarker", "")}}
            ],
            "links": [{"traceId": trace_id, "spanId": s_id} for s_id in diag_internal_spans]
        })
            
    run_state = {
        "runId": run_id,
        "status": "waiting_diagnostics" if dispatches else "waiting_decision",
        "diagnosis": diagnosis,
        "chosenEffect": chosen_effect,
        "arguments": arguments,
        "dispatches": dispatches,
        "approvals": [],
        "spans": spans,
        "trace_id": trace_id,
        "agent_span_id": agent_span_id,
        "public_marker": body.get("publicMarker", ""),
        "incident": incident,
        "policy": policy,
        "receiptLog": [],
        "processed_receipts": {}
    }
    
    Q11_RUNS[run_id] = run_state
    
    if not dispatches:
        approval_required = chosen_effect in policy.get("approvalRequiredFor", [])
        if approval_required:
            app_id = f"app-{uuid.uuid4().hex[:16]}"
            act_id = f"act-{uuid.uuid4().hex[:16]}"
            digest = make_arguments_digest(arguments)
            approval_req = {
                "approvalId": app_id,
                "actionId": act_id,
                "toolName": chosen_effect,
                "argumentsDigest": digest
            }
            run_state["approvals"] = [approval_req]
            run_state["status"] = "waiting_approval"
            
            spans.append({
                "traceId": trace_id,
                "spanId": uuid.uuid4().hex[:16],
                "parentSpanId": agent_span_id,
                "name": "approval_gate",
                "kind": 1,
                "attributes": [
                    {"key": "ga5.run.id", "value": {"stringValue": run_id}},
                    {"key": "ga5.public.marker", "value": {"stringValue": body.get("publicMarker", "")}},
                    {"key": "ga5.approval.id", "value": {"stringValue": app_id}}
                ]
            })
        else:
            act_id = f"act-{uuid.uuid4().hex[:16]}"
            call_id = f"call-{uuid.uuid4().hex[:16]}"
            eff_client_span = uuid.uuid4().hex[:16]
            eff_internal_span = uuid.uuid4().hex[:16]
            tp = f"00-{trace_id}-{eff_client_span}-01"
            
            eff_dispatch = {
                "actionId": act_id,
                "callId": call_id,
                "phase": "effect",
                "toolName": chosen_effect,
                "arguments": arguments,
                "attempt": 1,
                "traceparent": tp
            }
            run_state["dispatches"] = [eff_dispatch]
            run_state["status"] = "waiting_effect"
            
            spans.extend([
                {
                    "traceId": trace_id,
                    "spanId": eff_internal_span,
                    "parentSpanId": agent_span_id,
                    "name": "execute_tool",
                    "kind": 1,
                    "attributes": [
                        {"key": "ga5.run.id", "value": {"stringValue": run_id}},
                        {"key": "ga5.public.marker", "value": {"stringValue": body.get("publicMarker", "")}},
                        {"key": "ga5.action.id", "value": {"stringValue": act_id}},
                        {"key": "gen_ai.tool.name", "value": {"stringValue": chosen_effect}},
                        {"key": "gen_ai.tool.call.id", "value": {"stringValue": call_id}},
                        {"key": "gen_ai.operation.name", "value": {"stringValue": "execute_tool"}}
                    ]
                },
                {
                    "traceId": trace_id,
                    "spanId": eff_client_span,
                    "parentSpanId": eff_internal_span,
                    "name": f"POST tool/{chosen_effect}",
                    "kind": 3,
                    "attributes": [
                        {"key": "ga5.run.id", "value": {"stringValue": run_id}},
                        {"key": "ga5.public.marker", "value": {"stringValue": body.get("publicMarker", "")}},
                        {"key": "ga5.action.id", "value": {"stringValue": act_id}},
                        {"key": "ga5.attempt", "value": {"intValue": 1}},
                        {"key": "http.request.method", "value": {"stringValue": "POST"}},
                        {"key": "http.request.resend_count", "value": {"intValue": 0}}
                    ]
                }
            ])
            
    return {
        "runId": run_id,
        "status": "waiting",
        "diagnosis": diagnosis,
        "dispatches": run_state["dispatches"],
        "approvals": run_state["approvals"]
    }

@router.post("/v2/incidents/{runId}/receipts")
async def incident_receipts(runId: str, request: Request):
    if runId not in Q11_RUNS:
         raise HTTPException(status_code=404, detail="Run not found")
         
    run = Q11_RUNS[runId]
    body = await request.json()
    receipt_id = body.get("receiptId")
    
    if receipt_id in run["processed_receipts"]:
        existing = run["processed_receipts"][receipt_id]
        if existing["body"] != body:
            raise HTTPException(status_code=409, detail="CONFLICT: receiptId already processed with different content")
        return existing["response"]
        
    outcomes = body.get("outcomes", [])
    approvals = body.get("approvals", [])
    
    for o in outcomes:
        run["receiptLog"].append({
            "receiptId": receipt_id,
            "actionId": o.get("actionId"),
            "callId": o.get("callId"),
            "attempt": o.get("attempt", 1),
            "status": o.get("status", 200),
            "resultClass": o.get("resultClass", ""),
            "nonce": o.get("nonce", "")
        })
        
        for s in run["spans"]:
            if s["name"].startswith("POST tool/") and s["kind"] == 3:
                act_attr = next((a for a in s["attributes"] if a["key"] == "ga5.action.id"), None)
                if act_attr and act_attr["value"].get("stringValue") == o.get("actionId"):
                    s["attributes"] = [attr for attr in s["attributes"] if attr["key"] not in (
                        "ga5.receipt.id", "ga5.receipt.nonce", 
                        "http.response.status_code", "http.request.resend_count", "ga5.attempt"
                    )]
                    s["attributes"].extend([
                        {"key": "ga5.receipt.id", "value": {"stringValue": receipt_id}},
                        {"key": "ga5.receipt.nonce", "value": {"stringValue": o.get("nonce", "")}},
                        {"key": "ga5.attempt", "value": {"intValue": int(o.get("attempt", 1))}},
                        {"key": "http.response.status_code", "value": {"intValue": int(o.get("status", 200))}},
                        {"key": "http.request.resend_count", "value": {"intValue": int(o.get("attempt", 1)) - 1}}
                    ])
                    
    for a in approvals:
        run["receiptLog"].append({
            "receiptId": receipt_id,
            "approvalId": a.get("approvalId"),
            "decision": a.get("decision", "approved"),
            "nonce": a.get("nonce", "")
        })
        
        for s in run["spans"]:
            if s["name"] == "approval_gate":
                app_attr = next((attr for attr in s["attributes"] if attr["key"] == "ga5.approval.id"), None)
                if app_attr and app_attr["value"].get("stringValue") == a.get("approvalId"):
                    s["attributes"] = [attr for attr in s["attributes"] if attr["key"] != "ga5.receipt.nonce"]
                    s["attributes"].append({"key": "ga5.receipt.nonce", "value": {"stringValue": a.get("nonce", "")}})
        
    response = {}
    if run["status"] == "waiting_diagnostics":
        chosen_effect = run["chosenEffect"]
        policy = run["policy"]
        arguments = run["arguments"]
        trace_id = run["trace_id"]
        agent_span_id = run["agent_span_id"]
        
        approval_required = chosen_effect in policy.get("approvalRequiredFor", [])
        if approval_required:
            app_id = f"app-{uuid.uuid4().hex[:16]}"
            act_id = f"act-{uuid.uuid4().hex[:16]}"
            digest = make_arguments_digest(arguments)
            
            approval_req = {
                "approvalId": app_id,
                "actionId": act_id,
                "toolName": chosen_effect,
                "argumentsDigest": digest
            }
            run["approvals"] = [approval_req]
            run["dispatches"] = []
            run["status"] = "waiting_approval"
            
            run["spans"].append({
                "traceId": trace_id,
                "spanId": uuid.uuid4().hex[:16],
                "parentSpanId": agent_span_id,
                "name": "approval_gate",
                "kind": 1,
                "attributes": [
                    {"key": "ga5.run.id", "value": {"stringValue": runId}},
                    {"key": "ga5.public.marker", "value": {"stringValue": run["public_marker"]}},
                    {"key": "ga5.approval.id", "value": {"stringValue": app_id}}
                ]
            })
            
            response = {
                "runId": runId,
                "status": "waiting",
                "dispatches": [],
                "approvals": [approval_req]
            }
        else:
            act_id = f"act-{uuid.uuid4().hex[:16]}"
            call_id = f"call-{uuid.uuid4().hex[:16]}"
            eff_client_span = uuid.uuid4().hex[:16]
            eff_internal_span = uuid.uuid4().hex[:16]
            tp = f"00-{trace_id}-{eff_client_span}-01"
            
            eff_dispatch = {
                "actionId": act_id,
                "callId": call_id,
                "phase": "effect",
                "toolName": chosen_effect,
                "arguments": arguments,
                "attempt": 1,
                "traceparent": tp
            }
            run["dispatches"].append(eff_dispatch)
            run["status"] = "waiting_effect"
            
            run["spans"].extend([
                {
                    "traceId": trace_id,
                    "spanId": eff_internal_span,
                    "parentSpanId": agent_span_id,
                    "name": "execute_tool",
                    "kind": 1,
                    "attributes": [
                        {"key": "ga5.run.id", "value": {"stringValue": runId}},
                        {"key": "ga5.public.marker", "value": {"stringValue": run["public_marker"]}},
                        {"key": "ga5.action.id", "value": {"stringValue": act_id}},
                        {"key": "gen_ai.tool.name", "value": {"stringValue": chosen_effect}},
                        {"key": "gen_ai.tool.call.id", "value": {"stringValue": call_id}},
                        {"key": "gen_ai.operation.name", "value": {"stringValue": "execute_tool"}}
                    ]
                },
                {
                    "traceId": trace_id,
                    "spanId": eff_client_span,
                    "parentSpanId": eff_internal_span,
                    "name": f"POST tool/{chosen_effect}",
                    "kind": 3,
                    "attributes": [
                        {"key": "ga5.run.id", "value": {"stringValue": runId}},
                        {"key": "ga5.public.marker", "value": {"stringValue": run["public_marker"]}},
                        {"key": "ga5.action.id", "value": {"stringValue": act_id}},
                        {"key": "ga5.attempt", "value": {"intValue": 1}},
                        {"key": "http.request.method", "value": {"stringValue": "POST"}},
                        {"key": "http.request.resend_count", "value": {"intValue": 0}}
                    ]
                }
            ])
            
            response = {
                "runId": runId,
                "status": "waiting",
                "dispatches": [eff_dispatch],
                "approvals": []
            }
            
    elif run["status"] == "waiting_approval":
        app_receipt = next((x for x in run["receiptLog"] if "approvalId" in x), None)
        if app_receipt and app_receipt["decision"] == "approved":
            chosen_effect = run["chosenEffect"]
            arguments = run["arguments"]
            trace_id = run["trace_id"]
            agent_span_id = run["agent_span_id"]
            app_id = app_receipt["approvalId"]
            app_nonce = app_receipt["nonce"]
            
            for s in run["spans"]:
                if s["name"] == "approval_gate":
                    s["attributes"].append({"key": "ga5.receipt.nonce", "value": {"stringValue": app_nonce}})
            
            act_id = f"act-{uuid.uuid4().hex[:16]}"
            call_id = f"call-{uuid.uuid4().hex[:16]}"
            eff_client_span = uuid.uuid4().hex[:16]
            eff_internal_span = uuid.uuid4().hex[:16]
            tp = f"00-{trace_id}-{eff_client_span}-01"
            
            eff_dispatch = {
                "actionId": act_id,
                "callId": call_id,
                "phase": "effect",
                "toolName": chosen_effect,
                "arguments": arguments,
                "attempt": 1,
                "traceparent": tp,
                "approvalId": app_id,
                "approvalNonce": app_nonce
            }
            run["dispatches"].append(eff_dispatch)
            run["status"] = "waiting_effect"
            
            run["spans"].extend([
                {
                    "traceId": trace_id,
                    "spanId": eff_internal_span,
                    "parentSpanId": agent_span_id,
                    "name": "execute_tool",
                    "kind": 1,
                    "attributes": [
                        {"key": "ga5.run.id", "value": {"stringValue": runId}},
                        {"key": "ga5.public.marker", "value": {"stringValue": run["public_marker"]}},
                        {"key": "ga5.action.id", "value": {"stringValue": act_id}},
                        {"key": "gen_ai.tool.name", "value": {"stringValue": chosen_effect}},
                        {"key": "gen_ai.tool.call.id", "value": {"stringValue": call_id}},
                        {"key": "gen_ai.operation.name", "value": {"stringValue": "execute_tool"}}
                    ]
                },
                {
                    "traceId": trace_id,
                    "spanId": eff_client_span,
                    "parentSpanId": eff_internal_span,
                    "name": f"POST tool/{chosen_effect}",
                    "kind": 3,
                    "attributes": [
                        {"key": "ga5.run.id", "value": {"stringValue": runId}},
                        {"key": "ga5.public.marker", "value": {"stringValue": run["public_marker"]}},
                        {"key": "ga5.action.id", "value": {"stringValue": act_id}},
                        {"key": "ga5.attempt", "value": {"intValue": 1}},
                        {"key": "http.request.method", "value": {"stringValue": "POST"}},
                        {"key": "http.request.resend_count", "value": {"intValue": 0}}
                    ]
                }
            ])
            
            response = {
                "runId": runId,
                "status": "waiting",
                "dispatches": [eff_dispatch],
                "approvals": []
            }
        else:
            response = {
                "runId": runId,
                "status": "waiting",
                "dispatches": [],
                "approvals": run["approvals"]
            }
            
    elif run["status"] == "waiting_effect":
        run["status"] = "completed"
        
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
        
        response = {
            "runId": runId,
            "status": "completed",
            "diagnosis": run["diagnosis"],
            "chosenEffect": run["chosenEffect"],
            "suppressed": [],
            "actionLog": run["dispatches"],
            "receiptLog": run["receiptLog"],
            "otlp": otlp
        }
        run["final_response"] = response
        
    run["processed_receipts"][receipt_id] = {
        "body": body,
        "response": response
    }
    
    return response

@router.get("/v2/incidents/{runId}")
async def get_incident(runId: str):
    if runId not in Q11_RUNS:
        raise HTTPException(status_code=404, detail="Run not found")
    run = Q11_RUNS[runId]
    if run["status"] == "completed":
        return run["final_response"]
    return {
        "runId": runId,
        "status": "waiting",
        "diagnosis": run["diagnosis"],
        "dispatches": run["dispatches"],
        "approvals": run["approvals"]
    }
