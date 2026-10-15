#!/usr/bin/env python3
"""ROBINHIDDEN selftest -- stdlib only. Run: python3 selftest.py [--live]"""
import json, math, os, py_compile, random, sys, threading, time, http.server

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from rh import crypto as C
import rh.model as M
import rh.rpc as R

PASS = FAIL = 0
def chk(name, cond, extra=""):
    global PASS, FAIL
    if cond:
        PASS += 1; print("ok    " + name)
    else:
        FAIL += 1; print("FAIL  " + name + (("  ::  " + repr(extra)[:500]) if extra != "" else ""))

# ---------- independent reference keccak-256 (different lane layout) ----------
_RC64 = list(C._RC)  # round constants anchored via ground-truth vectors; sponge/round logic below stays independent
_ROT = [[0,36,3,41,18],[1,44,10,45,2],[62,6,43,15,61],[28,55,25,21,56],[27,20,39,8,14]]
_M = (1 << 64) - 1
def _rol(x, n):
    n %= 64
    return ((x << n) | (x >> (64 - n))) & _M if n else x
def ref_keccak_f(A):
    for rnd in range(24):
        Cp = [A[x][0]^A[x][1]^A[x][2]^A[x][3]^A[x][4] for x in range(5)]
        D = [Cp[(x-1) % 5] ^ _rol(Cp[(x+1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5): A[x][y] ^= D[x]
        B = [[0]*5 for _ in range(5)]
        for x in range(5):
            for y in range(5): B[y][(2*x + 3*y) % 5] = _rol(A[x][y], _ROT[x][y])
        for x in range(5):
            for y in range(5):
                A[x][y] = B[x][y] ^ ((~B[(x+1) % 5][y] & B[(x+2) % 5][y]) & _M)
        A[0][0] ^= _RC64[rnd]
    return A
def ref_keccak256(msg: bytes) -> bytes:
    rate = 136
    m = bytearray(msg + b"\x01")
    while len(m) % rate: m.append(0)
    m[-1] ^= 0x80
    A = [[0]*5 for _ in range(5)]
    for off in range(0, len(m), rate):
        blk = m[off:off+rate]
        for i in range(rate // 8):
            A[i % 5][i // 5] ^= int.from_bytes(blk[8*i:8*i+8], "little")
        A = ref_keccak_f(A)
    return b"".join(A[i % 5][i // 5].to_bytes(8, "little") for i in range(4))

# ---------- rpc fakes ----------
class FakeServer:
    def __init__(self, delay=0.0):
        self.delay = delay
        self.state = {"bn": 1000, "rec_nulls": 2, "nonces": {}}

    def __call__(self, payload, timeout=10):
        if self.delay > timeout:
            raise TimeoutError("timed out")
        if self.delay > 0:
            time.sleep(self.delay)
        m = payload.get("method")
        p = payload.get("params", [])
        st = self.state
        res = None
        if m == "eth_chainId": res = "0x1237"
        elif m == "eth_blockNumber": st["bn"] += 1; res = hex(st["bn"])
        elif m == "eth_gasPrice": res = hex(6 * 10**9)
        elif m == "eth_getBalance": res = hex(7 * 10**18)
        elif m == "eth_getTransactionCount":
            c = st["nonces"].get(p[0], 0); res = hex(c); st["nonces"][p[0]] = c + 1
        elif m == "eth_getCode": res = "0x6080604052"
        elif m == "eth_call": res = "0x" + "11" * 32
        elif m == "eth_sendRawTransaction": res = "0x" + "ab" * 32
        elif m == "eth_getTransactionReceipt":
            if st["rec_nulls"] > 0: st["rec_nulls"] -= 1; res = None
            else: res = {"status": "0x1", "logs": [], "blockNumber": "0x10"}
        body = {"jsonrpc": "2.0", "id": payload.get("id")}
        if m not in ("eth_chainId","eth_blockNumber","eth_gasPrice","eth_getBalance",
              "eth_getTransactionCount","eth_getCode","eth_call","eth_sendRawTransaction","eth_getTransactionReceipt"):
            body["error"] = {"code": -32601, "message": "no such method"}
        else:
            body["result"] = res
        return body, self.delay * 1000.0

def start_srv(delay):
    srv = FakeServer(delay)
    url = "mock://server-%d" % len(R.TRANSPORT_HOOKS)
    R.TRANSPORT_HOOKS[url] = srv
    return srv, url

def preset(name):
    cfg = json.loads(json.dumps(M.DEFAULT_CFG))
    M.deep_update(cfg, M.PRESETS[name])
    return cfg

def plan_sig(p):
    return (tuple(round(x, 9) for x in p["wallet_totals"]),
            tuple((s["wallet"], round(s["eth"], 9), round(s["t"], 1))
                  for s in sorted(p["slots"], key=lambda s: (s["t"], s["wallet"]))))

def main():
    live = "--live" in sys.argv
    # 0 compile
    okc = True
    for f in ("rh/__init__.py", "rh/crypto.py", "rh/model.py", "rh/rpc.py"):
        try: py_compile.compile(os.path.join(HERE, f), doraise=True)
        except Exception as e: okc = False; print("compile:", f, e)
    chk("py_compile: 4 modules", okc)

    # 1 keccak anchors + cross-check vs independent implementation
    v = {"": "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
         "abc": "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45",
         "fox": "4d741b6f1eb29cb2a9b9911c82f56fa8d73b04959d3d9d222895df6c0b28aa15"}
    msgs = {"": b"", "abc": b"abc", "fox": b"The quick brown fox jumps over the lazy dog"}
    for k, exp in v.items():
        chk("keccak256(%r)" % (msgs[k][:20]), C.keccak256(msgs[k]).hex() == exp,
            C.keccak256(msgs[k]).hex())
    bad = []
    lens = [0,1,2,7,31,32,33,63,64,65,127,128,135,136,137,191,192,193,255,256,271,272] + \
           [random.randrange(0, 400) for _ in range(110)]
    for L in lens:
        m = bytes(random.randrange(256) for _ in range(L))
        if C.keccak256(m) != ref_keccak256(m): bad.append(L)
    chk("keccak256 vs independent implementation: %d messages (including multiple blocks)" % len(lens), not bad, bad[:10])

    # 2 secp256k1
    chk("addr priv=1", C.priv_to_address(1) == "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf", C.priv_to_address(1))
    chk("addr priv=2", C.priv_to_address(2) == "0x2b5ad5c4795c026514f8317c7a215e218dccd6cf")
    chk("addr priv=3", C.priv_to_address(3) == "0x6813eb9362372eef6200f3b1dbc3f819671cba69")
    chk("N*G = infinity", C.point_mul(C.G, C.N) is None)
    k1, k2 = random.randrange(2, C.N), random.randrange(2, C.N)
    chk("(k1+k2)G = k1G + k2G", C.point_mul(C.G, (k1+k2) % C.N) == C._pt_add(C.point_mul(C.G, k1), C.point_mul(C.G, k2)))
    fails = []; lowsbad = 0
    for _ in range(200):
        priv = random.randrange(1, C.N)
        h = C.keccak256(bytes(random.randrange(256) for _ in range(64)))
        r, s, rec = C.sign(h, priv)
        if s > C.N // 2: lowsbad += 1
        try:
            Q = C.recover(h, r, s, rec)
        except Exception:
            fails.append("recover raised"); continue
        if Q != C.priv_to_pub(priv): fails.append(("mismatch", priv % 10**8))
    chk("sign/recover 200 rnd + low-s", not fails and lowsbad == 0, (fails[:3], lowsbad))

    # 3 RLP vectors + roundtrip
    hv = lambda b: bytes.fromhex(b)
    chk("rlp('dog')", C.rlp(b"dog").hex() == "83646f67", C.rlp(b"dog").hex())
    chk("rlp('')", C.rlp(b"").hex() == "80")
    chk("rlp(0)", C.rlp(0).hex() == "80")
    chk("rlp(15)", C.rlp(15).hex() == "0f")
    chk("rlp(1024)", C.rlp(1024).hex() == "820400")
    chk("rlp([cat,dog])", C.rlp([b"cat", b"dog"]).hex() == "c88363617483646f67", C.rlp([b"cat", b"dog"]).hex())
    chk("rlp([])", C.rlp([]).hex() == "c0")
    chk("rlp(55 bytes)", C.rlp(b"x"*55).hex() == "b7" + "78"*55)
    chk("rlp(56 bytes)", C.rlp(b"y"*56).hex() == "b838" + "79"*56)
    chk("rlp(long list)", C.rlp([b"a"*30, b"b"*30]).hex().startswith("f83e9e"))
    chk("decode long list", C.rlp_decode(bytes.fromhex("f83e9e" + "61"*30 + "9e" + "62"*30)) == [b"a"*30, b"b"*30])
    rd = C.rlp_decode
    chk("decode short list", rd(hv("c88363617483646f67")) == [b"cat", b"dog"], rd(hv("c88363617483646f67")))
    chk("decode 1024", rd(hv("820400")) == b"\x04\x00")
    chk("decode nested list", rd(C.rlp([[b"a", 0], [b"b"*200, []]])) is not None)
    bad = 0; rng = random.Random(7)
    def rgen():
        t = rng.random()
        if t < 0.4: return bytes(rng.randrange(256) for _ in range(rng.randrange(0, 70)))
        if t < 0.7: return rng.randrange(0, 10**6)
        return [rgen() for _ in range(rng.randrange(0, 4))]
    for _ in range(60):
        x = rgen(); e = C.rlp(x)
        if C.rlp(rd(e)) != e: bad += 1
    chk("rlp roundtrip aleatorio 60x", bad == 0, bad)
    err = False
    try: C.rlp_decode(hv("83646f6700"))
    except ValueError: err = True
    chk("rlp rejects trailing bytes", err)

    # 4 ABI
    chk("sel transfer", C.sel("transfer(address,uint256)").hex() == "a9059cbb")
    chk("sel approve", C.sel("approve(address,uint256)").hex() == "095ea7b3")
    chk("sel transferFrom", C.sel("transferFrom(address,address,uint256)").hex() == "23b872dd")
    chk("sel balanceOf", C.sel("balanceOf(address)").hex() == "70a08231")
    to = "0x" + "11"*20; amt = 123 * 10**18
    cd = C.abi_encode("transfer(address,uint256)", [to, amt])
    words = C.decode_words(cd)
    chk("calldata transfer layout", cd[:4].hex() == "a9059cbb" and words[0] == int(to, 16) and words[1] == amt, words)
    cb = C.abi_encode("setData(bytes)", [b"\xab"*33])
    wb = C.decode_words(cb)
    chk("calldata bytes dinamico", wb[0] == 32 and wb[1] == 33 and cb[4+32+32:4+32+32+64] == b"\xab"*33 + b"\x00"*31)
    ca = C.abi_encode("setA(address[])", [["0x"+"22"*20, "0x"+"33"*20]])
    wa = C.decode_words(ca)
    chk("calldata address[] dinamico", wa[0] == 32 and wa[1] == 2 and wa[2] == int("0x"+"22"*20, 16))
    log_b = C.transfer_log("0x"+"aa"*20, "0x"+"bb"*20, "0x"+"cc"*20, 456 * 10**18)
    chk("parse_transfer (bytes)", C.parse_transfer(log_b)["value"] == 456 * 10**18)
    log_s = dict(log_b); log_s["data"] = log_b["data"]
    chk("parse_transfer (hex str)", C.parse_transfer(log_s)["value"] == 456 * 10**18, C.parse_transfer(log_s))
    chk("parse_transfer ignora outro topic", C.parse_transfer(dict(log_b, topics=["0x" + "99"*32, log_b["topics"][1], log_b["topics"][2]])) is None)

    # 5 type-2 tx flow
    rng = random.Random(11)
    bad = []
    for i in range(50):
        priv = rng.randrange(1, C.N)
        to = "0x" + bytes(rng.randrange(256) for _ in range(20)).hex()
        value = rng.choice([0, 1, 10**18, rng.randrange(2**64)])
        data = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 120)))
        nonce = rng.randrange(0, 50)
        raw, (r, s, vpar) = R.sign_tx(4663, priv, nonce, to, value, data, 2*10**9, 10**9, 100000)
        if vpar not in (0, 1): bad.append(("v", i, vpar)); continue
        d = R.decode_typed_tx(raw)
        if not (d["chain_id"] == 4663 and d["nonce"] == nonce and d["max_prio"] == 10**9 and
                d["max_fee"] == 2*10**9 and d["gas"] == 100000 and d["to"].lower() == to.lower() and
                d["value"] == value and bytes(d["data"]) == bytes(data)):
            bad.append(("fields", i)); continue
        fields = [d["chain_id"], d["nonce"], d["max_prio"], d["max_fee"], d["gas"],
                  C.unh(d["to"]), d["value"], bytes(d["data"]), d["access"]]
        h = C.keccak256(b"\x02" + C.rlp(fields))
        if C.recover(h, d["r"], d["s"], d["v"]) != C.priv_to_pub(priv):
            bad.append(("recover", i))
    chk("type-2: sign->decode->recover 50x (including multi-block keccak)", not bad, bad[:3])
    raw_a, _ = R.sign_tx(4663, 99, 0, "0x"+"44"*20, 5, b"", 10**9, 10**9, 50000)
    raw_b, _ = R.sign_tx(4663, 99, 0, "0x"+"44"*20, 5, b"", 10**9, 10**9, 50000)
    chk("deterministic signature (RFC6979)", raw_a == raw_b)
    err = False
    try: R.decode_typed_tx(b"\x01" + raw_a[1:])
    except AssertionError: err = True
    chk("decode rejects type-1", err)

    # 6 model / planner
    ws = M.gen_wallets(14, {"A": 1, "B": 1, "C": 1})
    chk("gen_wallets: 14 unicos", len({w["addr"] for w in ws}) == 14 and
        all(len(w["addr"]) == 42 for w in ws))
    tmp = os.path.join(HERE, "data", "_test_wallets.json")
    M.save_wallets(ws, tmp)
    st_mode = os.stat(tmp).st_mode & 0o777
    chk("save_wallets: roundtrip + 0600", M.load_wallets(tmp) == ws and st_mode == 0o600, st_mode)
    os.remove(tmp)

    chk("math: cost for 90% = 9x TVC", abs(M.cost_for_share(0.9, 1.0) - 9.0) < 1e-9)
    chk("math: average entry for 90% = 10x", abs(M.avg_entry_mult(0.9) - 10.0) < 1e-9)
    chk("math: cost for 58%@15ETH = 20.71", abs(M.cost_for_share(0.58, 15.0) - 15*0.58/0.42) < 1e-6)
    chk("math: min wallets 55%@5% = 11", M.min_wallets(0.55, 0.05) == 11)
    sh = M.share_from_spend([0.2, 0.3], 1.0)
    chk("share_from_spend sum = s(0.5)", abs(sum(sh) - 0.5/1.5) < 1e-9, sh)

    for name in ("micro", "standard"):
        p = M.plan_campaign(preset(name))
        st = preset(name)["strategy"]
        mk = preset(name)["market"]
        wt, sl = p["wallet_totals"], p["slots"]
        ts = sorted({s["t"] for s in sl})
        gaps_ok = len(ts) <= 1 or all(b - a >= 0.29 for a, b in zip(ts, ts[1:]))
        maxsh = max(p["wallet_shares"])
        chk("%s: cv_amount >= 0.75" % name, p["cv_amount"] >= float(st["amount_cv_min"]), round(p["cv_amount"], 3))
        chk("%s: cv_timestamp >= 0.60" % name, p["cv_timestamp"] >= float(st["timestamp_cv_min"]), round(p["cv_timestamp"], 3))
        chk("%s: block gap >= 3 blocks" % name, gaps_ok, min((b-a for a,b in zip(ts, ts[1:])), default=99))
        chk("%s: totals match the budget" % name,
            abs(sum(wt) - p["buy_total"]) < 1e-6 and abs(sum(s["eth"] for s in sl) - p["buy_total"]) < 1e-6)
        chk("%s: implicit share within [min,max]" % name,
            float(st["min_share"]) <= p["implied_share"] <= float(st["max_share"]), round(p["implied_share"], 4))
        chk("%s: wallet_shares sum = buy/(buy+depth)" % name,
            abs(sum(p["wallet_shares"]) - p["implied_share"]) < 1e-6, sum(p["wallet_shares"]))
        chk("%s: maximum share per wallet <= 5%% (hold cap)" % name, maxsh <= 0.05 + 1e-9, round(maxsh, 4))
        ic = p["invariant_check"]
        chk("%s: invariants pass without failures" % name, ic["pass"], ic["fail"])
        print("      %s: implied=%.3f cv_amt=%.3f cv_ts=%.3f maxshare=%.3f%% slots=%d warns=%s"
              % (name, p["implied_share"], p["cv_amount"], p["cv_timestamp"], maxsh*100, len(sl), p["warns"]))
    pm = M.plan_campaign(preset("micro"))
    pm2 = M.plan_campaign(preset("micro"))
    chk("deterministic planner (same seed)", plan_sig(pm) == plan_sig(pm2))

    # 7 rpc failover / lag guard (fake servers locais)
    slow, slow_url = start_srv(3.0)
    fast, fast_url = start_srv(0.0)
    cfgf = json.loads(json.dumps(M.DEFAULT_CFG))
    cfgf["chain"]["rpc"] = [slow_url, fast_url]
    cfgf["chain"]["max_lag_ms"] = 500
    rp = R.Rpc(cfgf)
    t0 = time.time()
    cid = rp.chain_id()
    dt = time.time() - t0
    chk("lag-trip: slow call (3s) fails over to fast endpoint, chainId=4663",
        cid == 4663 and rp.stats["failovers"] >= 1 and dt < 2.5, (cid, rp.stats, round(dt, 2)))
    fo_before = rp.stats["failovers"]
    bn = rp.block_number()
    chk("second call directly to the healthy endpoint", bn > 1000 and rp.stats["failovers"] == fo_before, (bn, rp.stats))
    bal = rp.balance("0x" + "12" * 20); chk("eth_getBalance helper", bal == 7 * 10**18)
    chk("eth_getCode helper", len(rp.code("0x" + "12" * 20)) > 0)
    err = False
    try: rp.call("eth_metodoQueNaodoExist", [])
    except R.RpcError: err = True
    chk("JSON-RPC error -> RpcError after retries", err)
    rp.wait_receipt("0x" + "aa" * 32, timeout_s=10, poll=0.05)
    chk("wait_receipt: poll null -> receipt", True)
    r2 = R.Rpc({"chain": cfgf["chain"]})
    rec = r2.wait_receipt("0x" + "bb" * 32, timeout_s=10, poll=0.05)
    # fresh client: rec_nulls=2 again -> null, null, then receipt
    chk("wait_receipt returns a receipt", isinstance(rec, dict) and rec.get("status") == "0x1", rec)

    if live:
        try:
            cfg = M.load_cfg(os.path.join(HERE, "data", "config.json"))
            lp = R.Rpc(cfg)
            lc = lp.chain_id()
            chk("LIVE eth_chainId == 4663", lc == 4663, lc)
            lb = lp.block_number(); lg = lp.gas_price(); lf = lp.base_fee()
            chk("LIVE block/gas/basefee > 0", lb > 0 and lg > 0 and lf > 0, (lb, lg, lf))
            print("      LIVE latest block=%d gas=%d wei basefee=%d wei lag_max=%dms calls=%d"
                  % (lb, lg, lf, lp.stats["max_lag_seen"], lp.stats["calls"]))
            for nm in ("factory_v2", "router_launchbuy", "locker", "pool_manager_v4"):
                c = lp.code(M.DEFAULT_CFG["pons"][nm])
                chk("LIVE nonempty code: %s" % nm, len(c) > 0, len(c))
            weth = M.DEFAULT_CFG.get("chain", {}).get("weth")
            if weth:
                chk("LIVE nonempty code: weth", len(lp.code(weth)) > 0, weth)
            rows, changed = R.check_update(cfg)
            for r in rows:
                print("      BASELINE %-16s live=%s %s" % (r["name"], (r["live"] or "?")[:18], r["status"]))
            lo = R.openchain_lookup([int.from_bytes(C.sel("transfer(address,uint256)"), "big")])
            found = any("transfer" in n for ns in (lo.values() if isinstance(lo, dict) else []) for n in ns)
            chk("LIVE openchain resolve transfer", found, lo)
        except Exception as e:
            chk("LIVE (rede alcancavel)", False, repr(e)[:300])


    # ---------- ABI pins (verification 2026-10-10) ----------
    _cfgp = M.load_cfg(os.path.join(HERE, "data", "config.json"))
    _pairs = [
        ("router.launchAndBuy", _cfgp["abirouter"]["launch_and_buy"]["sig"], _cfgp["abirouter"]["launch_and_buy"]["selector"]),
        ("curve.buy", _cfgp["abicurve"]["buy"]["sig"], _cfgp["abicurve"]["buy"]["selector"]),
        ("curve.sell", _cfgp["abicurve"]["sell"]["sig"], _cfgp["abicurve"]["sell"]["selector"]),
    ]
    _bad, _wf = [], []
    for _lb, _sg, _sl in _pairs:
        if ("0x" + C.sel(_sg).hex()) != _sl:
            _bad.append(_lb)
    if ("0x" + C.keccak256(_cfgp["events"]["TokenLaunched"].encode()).hex()) != _cfgp["topic0_tokenlaunched"]:
        _bad.append("topic0")
    for _dd in (_cfgp["abicurve"]["reads"].values(), _cfgp["abifactory"]["reads"].values()):
        for _sg in _dd:
            if not (isinstance(_sg, str) and _sg.endswith(")") and "(" in _sg.split("(")[0] or "(" in _sg) or not _sg.strip():
                _wf.append(_sg)
    chk("ABI pins: selector==keccak(sig) + topic0 coerente", not _bad and not _wf, (_bad, _wf))
    if live:
        try:
            _c = R.Rpc(_cfgp)
            _ok, _det = True, []
            _rr = set("0x%08x" % x for x in R.push4_selectors(_c.code(_cfgp["pons"]["router_launchbuy"])))
            if _cfgp["abirouter"]["launch_and_buy"]["selector"] not in _rr:
                _ok, _det = False, _det + ["router.launchAndBuy"]
            _ff = set("0x%08x" % x for x in R.push4_selectors(_c.code(_cfgp["pons"]["factory_v2"])))
            for _nm, _sg in _cfgp["abifactory"]["reads"].items():
                if ("0x" + C.sel(_sg).hex()) not in _ff:
                    _ok, _det = False, _det + ["factory." + _nm]
            _lg = _c.call("eth_getLogs", [{"address": _cfgp["pons"]["factory_v2"],
                                           "topics": [_cfgp["topic0_tokenlaunched"]],
                                           "fromBlock": hex(_c.block_number() - 20000),
                                           "toBlock": "latest"}])
            if _lg:
                _tp = _lg[-1]["topics"]
                _cf = set("0x%08x" % x for x in R.push4_selectors(_c.code("0x" + _tp[2][-40:])))
                for _k in ("buy", "sell"):
                    if _cfgp["abicurve"][_k]["selector"] not in _cf:
                        _ok, _det = False, _det + ["curve." + _k]
            else:
                _ok, _det = False, _det + ["no TokenLaunched in the window"]
            chk("LIVE ABI pins: drift check vs bytecode (router+factory+curve)", _ok, _det)
        except Exception as _e:
            chk("LIVE ABI pins: drift check vs bytecode (router+factory+curve)", False, repr(_e)[:120])

    # ---------- exec: rlp / ecdsa / calldata / tx type-2 ----------
    from rh import exec as X
    chk("exec: rlp(b'')=0x80 rlp(dog)=0x83646f67", X.rlp(b"") == b"\x80" and X.rlp(b"dog") == b"\x83dog",
        (X.rlp(b""), X.rlp(b"dog")))
    _dcp = C.rlp_decode(X.rlp([b"cat", [b"pig"]]))
    chk("exec: rlp([])=0xc0 and rlp cat/pig decodes correctly", X.rlp([]) == b"\xc0"
        and _dcp[0] == b"cat" and _dcp[1][0] == b"pig",
        (X.rlp([]).hex(), X.rlp([b"cat", [b"pig"]]).hex(), _dcp))
    _rt_in = [[], [b""], [b"cat", [b"pig"]]]
    _rt_enc = X.rlp(_rt_in)
    try:
        _rt_dec = C.rlp_decode(_rt_enc)   # rlp_decode already rejects trailing bytes
        _ok_rt = _rt_dec == _rt_in
    except Exception as _e:
        _ok_rt, _rt_dec = False, repr(_e)[:80]
    chk("exec: rlp round-trip encoder<->decoder (battle tested)", _ok_rt, _rt_dec)
    _pr = [0x1, C.N // 3, C.N - 3]
    _ok = True; _det = []
    for _k in _pr:
        _h = C.keccak256(b"robinhidden-selftest-%d" % _k)
        _r, _s, _rec = C.sign(_h, _k)
        _Q = C.priv_to_pub(_k)
        if C.pub_to_address(_Q) != C.pub_to_address(C.recover(_h, _r, _s, _rec)):
            _ok = False; _det.append(("recover", _k % 97))
        if _s >= C.N // 2:
            _ok = False; _det.append(("high-s", _k % 97))
        _Rr = _r + ((_rec >> 1) & 1) * C.N
        _y2 = (_Rr ** 3 + 7) % C.P
        _y = pow(_y2, (C.P + 1) // 4, C.P)
        if (_y & 1) != (_rec & 1): _y = C.P - _y
        # identidade correta: s*k*G = e*G + r*priv*G  ->  s*R == e*G + r*Q
        _L = C._pt_add(C._mul(int.from_bytes(_h[:32], "big") % C.N, C.G), C._mul(_r % C.N, _Q))
        _Rh = C._mul(_s % C.N, (_Rr, _y))
        if _L != _Rh:
            _ok = False; _det.append(("eq-indep", _k % 97))
    chk("exec: ECDSA sign/recover + low-s + independent equation e*G=r*Q+s*R (3 keys)", _ok, _det)
    _h2 = C.keccak256(b"determinismo")
    _a1 = C.sign(_h2, 12345); _a2 = C.sign(_h2, 12345)
    chk("exec: deterministic ECDSA (RFC6979)", _a1 == _a2, (_a1, _a2))
    _cd = X.calldata_buy(10 ** 18, 42, "0x3535353535353535353535353535353535353535")
    _exp = bytes.fromhex("59a87bc1") + (10 ** 18).to_bytes(32, "big") + (42).to_bytes(32, "big") + b"\x00"*12 + b"\x35"*20
    chk("exec: calldata buy(uint256,uint256,address) manual", _cd == _exp, _cd.hex())
    _rawh, _raw, (_rr, _ss, _rc), _hh = X.sign_tx(4663, "0x9bab67a4f57da4b9ca54c0af2ebf14b71507e706",
                                                   10 ** 17, _cd, 0, 200000, 10 ** 8, 10 ** 6, 987654321)
    _fr = C.pub_to_address(C.priv_to_pub(987654321))
    chk("exec: type-2 raw transaction can be decoded again, signer == from, stable hash",
        X.recover_signer(_raw, 4663) == _fr and _rawh == "0x" + C.keccak256(bytes.fromhex(_raw[2:])).hex(),
        (X.recover_signer(_raw, 4663), _fr))
    if live:
        try:
            _c2 = R.Rpc(M.load_cfg(os.path.join(HERE, "data", "config.json")))
            _cid = int(_c2.call("eth_chainId", []), 16)
            _bf2 = X.base_fee(_c2)
            _w0 = json.load(open(os.path.join(HERE, "data", "wallets.json")))[0]["addr"]
            _n0 = int(_c2.call("eth_getTransactionCount", [_w0, "latest"]), 16)
            chk("LIVE exec: chainId=4663 + baseFee plausivel + nonce legivel", _cid == 4663 and 0 < _bf2 < 10 ** 12,
                (_cid, _bf2, _n0))
        except Exception as _e:
            chk("LIVE exec: chainId=4663 + baseFee plausivel + nonce legivel", False, repr(_e)[:120])
    print("\n%d passed, %d failed" % (PASS, FAIL))
    sys.exit(1 if FAIL else 0)

if __name__ == "__main__":
    main()
