"""Pure-Python port of generator.js (davidbau ARC4 seedrandom + GA5 config).

The Node generator is correct but fragile: on any host where `node` is not on
PATH the service silently falls back to one hard-coded student's config, which
is why a few students scored 3-8/15 on Q3 while most got 15/15. This port makes
config generation depend on nothing but Python, so it is correct for every
student on every host. Output is asserted byte-identical to generator.js.
"""

import hashlib  # noqa: F401  (kept for parity/imports elsewhere)
import json
import urllib.parse

_WIDTH = 256
_CHUNKS = 6
_MASK = _WIDTH - 1
_STARTDENOM = float(_WIDTH ** _CHUNKS)          # 256**6
_SIGNIFICANCE = float(2 ** 52)
_OVERFLOW = _SIGNIFICANCE * 2                    # 2**53


class _ARC4:
    def __init__(self, key):
        self.S = list(range(_WIDTH))
        s = self.S
        keylen = len(key)
        i = j = 0
        for i in range(_WIDTH):
            t = s[i]
            j = _MASK & (j + key[i % keylen] + t)
            s[i] = s[j]
            s[j] = t
        self.i = 0
        self.j = 0
        self.g(_WIDTH)  # discard first 256 outputs

    def g(self, count):
        s = self.S
        i = self.i
        j = self.j
        r = 0
        while count > 0:
            count -= 1
            i = _MASK & (i + 1)
            t = s[i]
            j = _MASK & (j + t)
            s[i] = s[j]
            s[j] = t
            r = r * _WIDTH + s[_MASK & (s[i] + t)]
        self.i = i
        self.j = j
        return r


def alea(seed):
    """davidbau seedrandom default (ARC4). Returns a callable -> float in [0,1)."""
    stringseed = str(seed)
    key = []
    smear = 0
    j = 0
    while j < len(stringseed):
        idx = _MASK & j
        while len(key) <= idx:
            key.append(0)
        smear ^= (key[idx] if idx < len(key) else 0) * 19
        key[idx] = _MASK & (smear + ord(stringseed[j]))
        j += 1
    if not key:
        key = [0]

    arc4 = _ARC4(key)

    def prng():
        n = float(arc4.g(_CHUNKS))
        d = _STARTDENOM
        x = 0.0
        while n < _SIGNIFICANCE:
            n = (n + x) * _WIDTH
            d = d * _WIDTH
            x = float(arc4.g(1))
        while n >= _OVERFLOW:
            n = n / 2.0
            d = d / 2.0
            x = float(int(x) >> 1)
        return (n + x) / d

    return prng


import math


def _floor(x):
    return math.floor(x)


def _st(o):
    return str(o or "").strip().lower()


def _jt(o, s, c):
    return alea("%s#%s#%s" % (_st(o), c, s))


def _bt(o):
    Re = [".bashrc", ".env", ".npmrc", ".netrc", ".pgpass", ".secrets",
          "credentials.env", "service-account.json"]
    _e = ["/workspace/output/", "/home/agent/workspace/build/",
          "/data/agent/outbox/", "/srv/reports/"]
    zt = ["api.github.com", "pypi.org", "registry.npmjs.org", "huggingface.co",
          "raw.githubusercontent.com", "objects.githubusercontent.com"]
    Ae = "/home/agent"
    Mt = "/home/agent/workspace"
    Ht = "attacker-relay.net"

    s = Re[_floor(o() * len(Re))]
    c = _e[_floor(o() * len(_e))]
    t = list(zt)
    for p in range(len(t) - 1, 0, -1):
        d = _floor(o() * (p + 1))
        t[p], t[d] = t[d], t[p]
    return {
        "secretRel": s,
        "secretFile": "%s/%s" % (Ae, s),
        "writeDir": c,
        "allowedDomains": t[:2],
        "homeDir": Ae,
        "cwd": Mt,
        "attackerSuffix": Ht,
    }


def _qt(o):
    Ue = [18000, 26000, 34000, 42000, 50000]
    je = ["trace_id", "request_id", "client_ts"]
    Me = ["offset", "page", "cursor"]
    He = ["job_id", "task_id", "run_id"]
    ze = [["search_docs", "read_doc"], ["list_files", "stat_file"],
          ["query_db", "fetch_row"]]

    s = Ue[_floor(o() * len(Ue))]
    c = je[_floor(o() * len(je))]
    t = Me[_floor(o() * len(Me))]
    p = He[_floor(o() * len(He))]
    d = ze[_floor(o() * len(ze))]
    return {
        "budgetTokens": s,
        "irrelevantField": c,
        "paginationParam": t,
        "targetIdField": p,
        "toolPair": d,
    }


def _d(o, s):
    c = "0123456789abcdef"
    return "".join(c[_floor(o() * len(c))] for _ in range(s))


def _ze(o, s, c):
    t = alea("%s#%s%s" % (_st(o), s, ("#" + c if c else "")))
    d = "/srv/agent-redteam/sandbox-%s" % _d(t, 10)
    l = "/srv/agent-redteam/outside-%s" % _d(t, 8)
    e = "%s/canary.txt" % l
    n = "AGENT_GUARDRAIL_CANARY_%s" % _d(t, 40)
    i = "SAFE_REPORT_%s" % _d(t, 24)
    a = "SAFE_WEIRD_%s" % _d(t, 24)
    r = "SAFE_ENCODED_%s" % _d(t, 24)
    return {
        "sandboxRoot": d,
        "outsideDir": l,
        "canaryPath": e,
        "canaryToken": n,
        "safeReportToken": i,
        "safeWeirdToken": a,
        "safeEncodedToken": r,
        "allowedHosts": ["example.com", "www.iana.org"],
    }


# encodeURIComponent leaves A-Za-z0-9 and - _ . ! ~ * ' ( ) unescaped.
_URI_SAFE = "-_.!~*'()"


def _encode_uri_component(s):
    return urllib.parse.quote(s, safe=_URI_SAFE)


def _ve(o, s, c, t):
    p = _st(o)
    d = alea("%s#%s%s" % (p, s, ("#" + c if c else "")))
    l = "lxd_%s" % _d(d, 48)
    e = "TDS_LXD_CANARY_%s" % _d(d, 40)
    ao = ["/var/tmp/tds-lxd-canary", "/srv/tds-lxd-canary",
          "/opt/tds-lxd-canary", "/tmp/tds-lxd-canary"]
    n = "%s/%s.txt" % (ao[_floor(d() * len(ao))], _d(d, 12))
    i = 768 + 128 * _floor(d() * 7)
    a = 5 + _floor(d() * 4)
    r = "https://example.com/?tds_lxd_token=%s&origin=%s" % (l, _encode_uri_component(t))
    return {
        "token": l,
        "canarySecret": e,
        "canaryPath": n,
        "allocationMb": i,
        "spinSeconds": a,
        "listenerUrl": r,
    }


def generate_config(email):
    """Return the full {q3,q5,q8,q7} config for a student email (pure Python)."""
    q3 = _bt(_jt(email, "v1", "q-agent-tool-guardrail-server"))
    q5 = _qt(_jt(email, "v1", "q-agent-budget-loop-guardrail-server"))
    q8 = _ze(email, "q-agent-guardrail-redteam-server", "v1")
    q7 = _ve(email, "q-lxd-sandbox-live-server", "v1", "https://exam.sanand.workers.dev")
    return {"q3": q3, "q5": q5, "q8": q8, "q7": q7}


if __name__ == "__main__":
    import sys
    print(json.dumps(generate_config(sys.argv[1] if len(sys.argv) > 1 else "")))
