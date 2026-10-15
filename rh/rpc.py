"""ROBINHIDDEN network layer: JSON-RPC with failover + lag guard, Blockscout explorer,
ABI auto-discovery (sync), contract-update baseline (check-update)."""
import json, math, os, ssl, sys, time, threading, urllib.request, urllib.error
from . import crypto as C

TRANSPORT_HOOKS = {}

class RpcError(RuntimeError):
    pass

class _PublicRpcError(RpcError):
    """Locally generated diagnostic; contains no URL or provider payload."""

def _unique_json_object(pairs):
    result={}
    for key,value in pairs:
        if key in result:raise _PublicRpcError('Duplicate JSON-RPC response member')
        result[key]=value
    return result

def _verified_ssl_context():
    """Use verified OS roots on macOS if this interpreter has no default roots.

    Explicit operator CA settings retain precedence. Never disable certificate
    verification or hostname checks to recover connectivity.
    """
    context = ssl.create_default_context()
    if (sys.platform == "darwin" and not context.cert_store_stats().get("x509_ca") and
            "SSL_CERT_FILE" not in os.environ and "SSL_CERT_DIR" not in os.environ and
            os.path.isfile("/etc/ssl/cert.pem")):
        context.load_verify_locations(cafile="/etc/ssl/cert.pem")
    return context

def _http_json(url, payload, timeout=10):
    if url in TRANSPORT_HOOKS:
        return TRANSPORT_HOOKS[url](payload, timeout)
    req = urllib.request.Request(url, data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json",
                                          "User-Agent": "robinhidden/3"})
    t0 = time.monotonic()
    with urllib.request.urlopen(req, timeout=timeout, context=_verified_ssl_context()) as r:
        body=r.read(8*1024*1024+1)
        if len(body)>8*1024*1024:raise _PublicRpcError('JSON-RPC response exceeds size limit')
        out = json.loads(body,object_pairs_hook=_unique_json_object)
    return out, (time.monotonic() - t0) * 1000.0

class Rpc:
    """Thread-safe failover JSON-RPC client. Measures round-trip lag; trips when lag > max_lag_ms."""
    def __init__(self, cfg):
        ch = cfg["chain"]
        if (not isinstance(ch.get('rpc'),list) or not ch['rpc'] or
                any(not isinstance(url,str) or not url.strip() for url in ch['rpc'])):
            raise ValueError('RPC configuration requires a nonempty endpoint list')
        self.urls = list(ch["rpc"])
        self.cur = 0
        lag=ch.get('max_lag_ms',2500)
        if type(lag) not in (int,float) or not math.isfinite(lag) or lag<=0:
            raise ValueError('RPC maximum lag must be a positive finite number')
        self.max_lag = float(lag)
        self.timeout = max(0.5, self.max_lag / 1000.0)
        self._id = 0
        self._lock = threading.Lock()
        self.stats = {"calls": 0, "failovers": 0, "max_lag_seen": 0.0}

    def call(self, method, params, retries=3):
        if type(retries) is not int or retries<1:
            raise ValueError('RPC retry count must be a positive integer')
        last = None
        total_attempts = retries * max(1, len(self.urls))
        for attempt in range(total_attempts):
            with self._lock:
                self._id += 1
                req_id = self._id
                url = self.urls[self.cur]
            try:
                res, lag = _http_json(url, {"jsonrpc": "2.0", "id": req_id,
                                            "method": method, "params": params}, self.timeout)
                if type(lag) not in (int,float) or not math.isfinite(lag) or lag<0:
                    raise _PublicRpcError('Invalid RPC latency measurement')
                with self._lock:
                    self.stats["calls"] += 1
                    self.stats["max_lag_seen"] = max(self.stats["max_lag_seen"], lag)

                if lag > self.max_lag:
                    with self._lock:
                        if len(self.urls) > 1:
                            self.cur = (self.cur + 1) % len(self.urls)
                        self.stats["failovers"] += 1
                    last = _PublicRpcError("lag %dms > %dms" % (lag, self.max_lag))
                    continue

                if not isinstance(res, dict):
                    raise _PublicRpcError('Malformed JSON-RPC response: expected object')

                if res.get('jsonrpc')!='2.0':
                    raise _PublicRpcError('Invalid JSON-RPC protocol version')

                if type(res.get('id')) is not int or res['id'] != req_id:
                    raise _PublicRpcError('mismatched response id')

                if "error" in res:
                    code=res['error'].get('code') if isinstance(res['error'],dict) else None
                    if type(code) is not int or 'result' in res:
                        raise _PublicRpcError('Malformed JSON-RPC error response')
                    raise _PublicRpcError('RPC provider error (code %d)'%code)

                if "result" not in res:
                    raise _PublicRpcError("Malformed JSON-RPC response: missing 'result' field")

                return res["result"]
            except (urllib.error.URLError, TimeoutError, ConnectionError, OSError, ValueError, RpcError) as e:
                last = e if isinstance(e,_PublicRpcError) else RpcError('RPC transport failure (%s)'%type(e).__name__)
                with self._lock:
                    if len(self.urls) > 1:
                        self.cur = (self.cur + 1) % len(self.urls)
                    self.stats["failovers"] += 1
                time.sleep(0.15)
        raise last

    # -- convenience ---------------------------------------------------------
    def chain_id(self): return int(self.call("eth_chainId", []), 16)
    def block_number(self): return int(self.call("eth_blockNumber", []), 16)
    def gas_price(self): return int(self.call("eth_gasPrice", []), 16)
    def base_fee(self):
        b = self.call("eth_getBlockByNumber", ["latest", False])
        return int(b["baseFeePerGas"], 16) if b and "baseFeePerGas" in b else 0
    def balance(self, addr): return int(self.call("eth_getBalance", [addr, "latest"]), 16)
    def nonce(self, addr): return int(self.call("eth_getTransactionCount", [addr, "latest"]), 16)
    def code(self, addr): return C.unh(self.call("eth_getCode", [addr, "latest"]) or "0x")
    def eth_call(self, to, data, block="latest"):
        return C.unh(self.call("eth_call", [{"to": to, "data": data}, block]) or "0x")
    def send_raw(self, raw): return self.call("eth_sendRawTransaction", ["0x" + raw.hex() if isinstance(raw, (bytes, bytearray)) else raw])
    def receipt(self, txh): return self.call("eth_getTransactionReceipt", [txh])
    def wait_receipt(self, txh, timeout_s=30, poll=0.12):
        t0 = time.time()
        while time.time() - t0 < timeout_s:
            r = self.receipt(txh)
            if r: return r
            time.sleep(poll)
        return None
    def get_logs(self, frm, to, address=None, topics=None):
        p = {"fromBlock": hex(frm), "toBlock": hex(to)}
        if address: p["address"] = address
        if topics: p["topics"] = topics
        return self.call("eth_getLogs", [p]) or []

def sign_tx(cfg_chain_id, priv, nonce, to, value, data, max_fee, max_prio, gas_limit):
    """Type-2 (EIP-1559) tx. Returns signed raw bytes."""
    to_bytes, data_bytes = C.validate_type2_inputs(cfg_chain_id, priv, nonce, to, value, data, max_fee, max_prio, gas_limit)
    unsigned = [cfg_chain_id, nonce, max_prio, max_fee, gas_limit,
                to_bytes, value, data_bytes, []]
    h = C.keccak256(b"\x02" + C.rlp(unsigned))
    r, s, rec = C.sign(h, priv)
    if type(rec) is not int or rec not in (0, 1):
        raise ValueError("Signature recovery identifier cannot be represented as type-2 yParity")
    v = rec
    return b"\x02" + C.rlp(unsigned + [v, r, s]), (r, s, v)

class InvalidTxTypeError(ValueError, AssertionError):
    """Exception for an invalid transaction format or type."""
    pass

def decode_typed_tx(raw: bytes):
    """Parse type-2 tx. Returns dict."""
    if not raw or raw[0] != 2:
        raise InvalidTxTypeError("expected type-2 tx (prefix 0x02 expected)")
    bi = lambda b: int.from_bytes(b, "big") if isinstance(b, (bytes, bytearray)) else b
    f = C.rlp_decode(raw[1:])
    (chain_id, nonce, mprio, mfee, gas, to, value, data, access, v, r, s) = f
    return {"chain_id": bi(chain_id), "nonce": bi(nonce), "max_prio": bi(mprio),
            "max_fee": bi(mfee), "gas": bi(gas), "to": "0x" + to.hex(),
            "value": bi(value), "data": data,
            "access": access, "v": bi(v), "r": bi(r), "s": bi(s)}

# ---------------- explorer (Blockscout v2) ----------------
class Explorer:
    def __init__(self, base):
        self.base = base.rstrip("/") + "/api/v2"

    def _get(self, path):
        try:
            req = urllib.request.Request(self.base + path, headers={"User-Agent": "robinhidden/3"})
            with urllib.request.urlopen(req, timeout=10) as r:
                return json.loads(r.read())
        except Exception:
            return None

    def address(self, addr):
        return self._get("/addresses/" + addr.lower())

    def labels(self, addr):
        """Public label: blockscout 'name' field + metadata notes."""
        info = self.address(addr)
        if not info:
            return None
        name = info.get("name") or ""
        meta = info.get("metadata") or {}
        notes = meta.get("notes") or ""
        return name or (notes[:80] if notes else None)

    def tx_count(self, addr):
        c = self._get("/addresses/" + addr.lower() + "/counters")
        return (c or {}).get("tx_count")

    def incoming(self, addr, limit=20):
        d = self._get("/addresses/" + addr.lower() + "/transactions?filter=to%7Cto%3A%3D%3D%3F")
        return (d or {}).get("items", [])[:limit]

# ---------------- ABI sync (auto-discovery) ----------------
def push4_selectors(code: bytes):
    out = set()
    i = 0
    while i < len(code) - 5:
        if code[i] == 0x63:  # PUSH4
            out.add(int.from_bytes(code[i+1:i+5], "big"))
            i += 5
        else:
            i += 1
    return sorted(out)

def _sig_names(d):
    """Defensively extract signature names from a response (4byte/samczsun)."""
    out = []
    rows = d.get("results") if isinstance(d, dict) else None
    if isinstance(rows, dict):
        rows = [rows]
    if not isinstance(rows, list) and isinstance(d, dict):
        n = d.get("name") or d.get("text_signature")
        if isinstance(n, str) and n:
            return [n]
    for x in rows or []:
        if not isinstance(x, dict):
            continue
        for k in ("text_signature", "text", "signature", "name", "func_signature"):
            v = x.get(k)
            if isinstance(v, str) and "(" in v:
                out.append(v)
                break
    seen, uniq = set(), []
    for v in out:
        if v not in seen:
            seen.add(v); uniq.append(v)
    return uniq[:6]

def _lookup_one_fallback(sig_hex):
    """One selector through 4byte.directory (a confirmed operational source)."""
    try:
        req = urllib.request.Request(
            "https://www.4byte.directory/api/v1/signatures/?hex_signature=" + sig_hex,
            headers={"User-Agent": "Mozilla/5.0 robinhidden/3"})
        with urllib.request.urlopen(req, timeout=4) as r:
            d = json.loads(r.read())
        return _sig_names(d)
    except Exception:
        return []

def openchain_lookup(selectors):
    """Resolve 4-byte selectors: batch through openchain; one-by-one samczsun/4byte fallback."""
    q = ",".join(hex(s) for s in selectors[:32])
    url = "https://api.openchain.xyz/signature-database/v1/lookup?function=" + q
    res = {}
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "robinhidden/3"})
        with urllib.request.urlopen(req, timeout=10) as r:
            d = json.loads(r.read())
        r = d.get("result") or {}
        for k, v in (r.get("function") or {}).items():
            res[k] = [x.get("name", "?") for x in v][:3]
        for k, v in (r.get("event") or {}).items():
            res["event:" + k] = [x.get("name", "?") for x in v][:3]
    except Exception:
        pass
    for s in selectors[:16]:
        if hex(s) not in res:
            nm = _lookup_one_fallback(hex(s))
            if nm:
                res[hex(s)] = nm[:3]
            time.sleep(0.15)
    return res

def abi_sync(cfg, addrs=None):
    """Discover candidate function signatures for configured contracts.
    Writes data/abi_cache.json. Human confirms the chosen sig into config."""
    rpc_ = Rpc(cfg)
    addrs = addrs or {k: v for k, v in cfg["pons"].items()}
    cache = {}
    for name, addr in addrs.items():
        code = rpc_.code(addr)
        if not code: continue
        sels = push4_selectors(code)
        found = openchain_lookup(sels)
        cache[name] = {"addr": addr, "code_hash": C.hexb(C.keccak256(code)),
                       "selectors_resolved": {k if isinstance(k, str) else hex(k): v for k, v in found.items()},
                       "selectors_total": len(sels)}
    return cache

# ---------------- contract-update baseline ----------------
BASELINE = {
    "factory_v2":      ("0x7ed598bcef8bd9edd8c97a195c6d13f40801ec7e", "__PENDING__"),
    "router_launchbuy":("0xe33e9e479df8802cb0866d5d05258bec4cf62948", "__PENDING__"),
    "locker":          ("0x267444d099b10fb5ed7c3cc7b7c767adca574952", "__PENDING__"),
    "hook":            ("0xe5e702641ea86f4ae6cc3cdaed2b886f976be044", "__PENDING__"),
    "deployer":        ("0x3711cea4feade896c913c68f01eda97cb06d1a42", "__PENDING__"),
    "executor":        ("0xc7819b64a1daecd7ec19856d026cb14efbd89046", "__PENDING__"),
    "pool_manager_v4": ("0x8366a39cc670b4001a1121b8f6a443a643e40951", "__PENDING__"),
    "weth":            ("0x0Bd7D308f8E1639FAb988df18A8011f41EAcAD73", "__PENDING__"),
    "factory_v1":      ("0xa5aab3f0c6eeadf30ef1d3eb997108e976351feb", "__PENDING__"),
}
BASELINE_DATE = "2026-10-09"

def check_update(cfg):
    out = []
    changed = []
    cfg_baseline = (cfg.get("baseline") or {}) if isinstance(cfg, dict) else {}
    # Validate the actual configured targets before making any code query.
    targets = []
    for name, (default_addr, base) in BASELINE.items():
        section = cfg.get("chain", {}) if name == "weth" else cfg.get("pons", {})
        if not isinstance(section, dict):
            raise ValueError("Invalid configured contract address section")
        addr = section.get(name, default_addr)
        if (not isinstance(addr, str) or not addr.startswith("0x") or len(addr) != 42 or
                any(ch not in "0123456789abcdefABCDEF" for ch in addr[2:]) or
                int(addr[2:], 16) == 0):
            raise ValueError("Invalid configured contract address for %s" % name)
        targets.append((name, addr, base))
    rpc_ = Rpc(cfg)
    for name, addr, base in targets:
        if name in cfg_baseline and cfg_baseline[name]:
            base = cfg_baseline[name]
        code = rpc_.code(addr)
        h = C.hexb(C.keccak256(code)) if code else "(no code)"
        if not code or len(code) == 0:
            status = "NO_CODE"
            changed.append(name)
        elif base == "__PENDING__":
            status = "PENDING_BASELINE"
        elif h.lower() != base.lower():
            status = "CHANGED"
            changed.append(name)
        else:
            status = "VERIFIED"
        out.append({"name": name, "addr": addr, "baseline": base, "live": h, "status": status})
    return out, changed
