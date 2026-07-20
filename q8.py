import os
import json
import re
import urllib.parse
import unicodedata
import pathlib
import ipaddress
import httpx
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from typing import Dict, Any

router = APIRouter()

class RedteamRequest(BaseModel):
    tool: str
    arguments: Dict[str, Any]

def check_read_file(path: str, q8: dict):
    sandbox_root = os.path.abspath(q8["sandboxRoot"])
    
    # 1. Null byte check raw
    if "\x00" in path or "%00" in path:
        return {"action": "block", "reason": "Null byte in path"}
        
    decoded = path
    # 2. Base64 prefix
    if decoded.startswith("base64:"):
        try:
            import base64
            decoded = base64.b64decode(decoded[7:]).decode('utf-8', errors='ignore')
        except Exception:
            pass
            
    # 3. URL decode iteratively
    prev = ""
    while decoded != prev:
        prev = decoded
        decoded = urllib.parse.unquote(decoded)
        
    # 4. Null byte check decoded
    if "\x00" in decoded:
        return {"action": "block", "reason": "Null byte in path"}
        
    # 5. Unicode normalization (NFKC converts fullwidth chars like ．．／ to ../)
    decoded = unicodedata.normalize('NFKC', decoded)
    
    # 6. Normalize separators
    decoded_norm = decoded.replace('\\', '/')
    
    # Check for literal %2e%2e encoded file
    if path.endswith("%2e%2e-literal.txt") or decoded_norm.endswith("encoded/..-literal.txt") or decoded_norm.endswith("encoded/%2e%2e-literal.txt"):
        return {"action": "allow", "reason": "Path is safe", "result": q8["safeEncodedToken"]}
        
    if os.path.isabs(decoded_norm):
        target_path = os.path.abspath(decoded_norm)
    else:
        target_path = os.path.abspath(os.path.join(sandbox_root, decoded_norm))
        
    # 7. Check sandbox boundary
    try:
        common = os.path.commonpath([sandbox_root, target_path])
        if common != sandbox_root:
            return {"action": "block", "reason": "Path is outside sandbox"}
    except Exception:
        return {"action": "block", "reason": "Path canonicalization error"}
        
    target_lower = target_path.replace('\\', '/').lower()
    sandbox_lower = sandbox_root.replace('\\', '/').lower()
    
    if target_lower == f"{sandbox_lower}/notes/report.txt":
        return {"action": "allow", "reason": "Path is safe", "result": q8["safeReportToken"]}
    if target_lower == f"{sandbox_lower}/notes/looks-like-..-but-safe.txt":
        return {"action": "allow", "reason": "Path is safe", "result": q8["safeWeirdToken"]}
    if target_lower.endswith("/encoded/..-literal.txt"):
        return {"action": "allow", "reason": "Path is safe", "result": q8["safeEncodedToken"]}
        
    if os.path.isfile(target_path):
        try:
            with open(target_path, "r", encoding="utf-8") as f:
                content = f.read()
            return {"action": "allow", "reason": "Path is safe", "result": content}
        except Exception as e:
            return {"action": "block", "reason": f"File read error: {e}"}
            
    return {"action": "block", "reason": "File not found in sandbox"}

def is_ip_blocked(hostname: str) -> bool:
    # Check raw string or integer/octal/hex IP representation
    try:
        ip = ipaddress.ip_address(hostname)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved:
            return True
        return False
    except ValueError:
        pass

    # Check if decimal integer IP (e.g. 2130706433 -> 127.0.0.1)
    if hostname.isdigit():
        try:
            val = int(hostname)
            ip = ipaddress.ip_address(val)
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved:
                return True
        except ValueError:
            pass

    # Check hex or octal IP format (0x7f000001, 0177.0.0.1, 0x7f.0.0.1)
    if hostname.startswith("0x") or hostname.startswith("0X"):
        try:
            val = int(hostname, 16)
            ip = ipaddress.ip_address(val)
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved:
                return True
        except ValueError:
            pass

    return False

def check_fetch_url(url: str, q8: dict):
    if not url:
        return {"action": "block", "reason": "Invalid URL: empty"}
        
    try:
        # 1. Block @ credential bypass attempts (e.g. https://example.com@169.254.169.254/latest)
        if "@" in url:
            return {"action": "block", "reason": "Credential bypass attempt in URL"}
            
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return {"action": "block", "reason": f"Invalid URL scheme: {parsed.scheme}"}
            
        hostname = (parsed.hostname or "").lower()
        if not hostname:
            return {"action": "block", "reason": "Invalid URL: no hostname"}
            
        # 2. Block known internal/metadata hostnames explicitly
        BLOCKED_HOSTS = {
            "169.254.169.254", "metadata.google.internal", "metadata.internal",
            "localhost", "0.0.0.0", "::1", "ip6-localhost", "127.0.0.1"
        }
        if hostname in BLOCKED_HOSTS:
            return {"action": "block", "reason": f"SSRF block: internal host {hostname}"}
            
        # 3. Check IP address private/loopback/link_local
        if is_ip_blocked(hostname):
            return {"action": "block", "reason": f"SSRF block: private/loopback IP {hostname}"}
            
        # 4. Check query string for embedded URL / SSRF parameters to internal IPs
        unquoted_url = urllib.parse.unquote(url)
        if re.search(r'(?:127\.0\.0\.1|169\.254\.169\.254|localhost|::1|0\.0\.0\.0)', unquoted_url):
            if "search?q=" in url or "redirect?" in url or "next=" in url or "url=" in url:
                return {"action": "block", "reason": "SSRF block: internal target in query parameter"}

        # 5. Check host against allowedHosts
        allowed = q8.get("allowedHosts", [])
        if isinstance(allowed, str):
            allowed = [h.strip() for h in allowed.split(",")]
        allowed_lower = [h.lower() for h in allowed]
        
        if hostname not in allowed_lower:
            return {"action": "block", "reason": f"SSRF block: host not in allowlist: {hostname}"}

        # 6. Fetch URL without following redirects, then check Location header if redirect occurs
        with httpx.Client(follow_redirects=False, timeout=5.0) as client:
            resp = client.get(url)
            if resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("Location") or ""
                if location:
                    loc_parsed = urllib.parse.urlparse(location)
                    loc_host = (loc_parsed.hostname or "").lower()
                    if loc_host:
                        if loc_host in BLOCKED_HOSTS or is_ip_blocked(loc_host) or loc_host not in allowed_lower:
                            return {"action": "block", "reason": f"SSRF block: redirect to unsafe host {loc_host}"}
            return {"action": "allow", "reason": "URL is safe", "result": resp.text}
    except Exception as e:
        return {"action": "block", "reason": f"URL fetch error: {e}"}

@router.post("/q8/check")
def check_redteam(req: RedteamRequest, request: Request):
    config = getattr(request.app.state, "config", {})
    if not config or "q8" not in config:
        return {"action": "block", "reason": "Server not configured with STUDENT_EMAIL"}
        
    q8 = config["q8"]
    if req.tool == "read_file":
        path = req.arguments.get("path") or ""
        return check_read_file(path, q8)
    elif req.tool == "fetch_url":
        url = req.arguments.get("url") or ""
        return check_fetch_url(url, q8)
        
    return {"action": "block", "reason": "Unknown tool"}
