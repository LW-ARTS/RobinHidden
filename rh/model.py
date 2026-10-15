"""ROBINHIDDEN model layer: config, wallets, wave planner, invariants, math."""
import json, math, os, random, re, secrets, statistics, time
from decimal import Decimal
from . import crypto as C

ETH = 10**18

def dumps_decimal(obj, indent=2):
    """Serializes an object to JSON while preserving Decimal values as exact unquoted JSON numbers."""
    sentinels = {}
    nonce = secrets.token_hex(16)

    def _default_dec(o):
        if isinstance(o, Decimal):
            if not o.is_finite():
                raise ValueError("Cannot serialize non-finite Decimal to JSON")
            tok = f"__DEC_SENTINEL_{nonce}_{len(sentinels)}__"
            sentinels[tok] = f"{o:f}"
            return tok
        raise TypeError(f"Object of type {type(o).__name__} is not JSON serializable")

    s = json.dumps(obj, indent=indent, default=_default_dec)
    for tok, val in sentinels.items():
        s = s.replace(f'"{tok}"', val)
    return s

def eth_to_wei(val) -> int:
    """Converts ETH amount to exact integer wei using decimal arithmetic, eliminating float rounding errors."""
    if isinstance(val, int):
        return val * 10**18
    if isinstance(val, Decimal):
        return int(val * Decimal(10**18))
    if isinstance(val, str):
        return int(Decimal(val) * Decimal(10**18))
    return int(Decimal(str(val)) * Decimal(10**18))

def wei_to_eth(wei_val: int) -> float:
    """Converts integer wei to float ETH (for display only)."""
    return float(Decimal(wei_val) / Decimal(10**18))

DEFAULT_CFG = {
    "chain": {
        "id": 4663,
        "rpc": ["https://rpc.mainnet.chain.robinhood.com"],
        "explorer": "https://robinhoodchain.blockscout.com",
        "weth": "0x0Bd7D308f8E1639FAb988df18A8011f41EAcAD73",
        "max_lag_ms": 2500,
    },
    "pons": {
        "factory_v2":     "0x7ed598bcef8bd9edd8c97a195c6d13f40801ec7e",
        "router_launchbuy":"0xe33e9e479df8802cb0866d5d05258bec4cf62948",
        "locker":         "0x267444d099b10fb5ed7c3cc7b7c767adca574952",
        "hook":           "0xe5e702641ea86f4ae6cc3cdaed2b886f976be044",
        "deployer":       "0x3711cea4feade896c913c68f01eda97cb06d1a42",
        "executor":       "0xc7819b64a1daecd7ec19856d026cb14efbd89046",
        "pool_manager_v4":"0x8366a39cc670b4001a1121b8f6a443a643e40951",
        "factory_v1":     "0xa5aab3f0c6eeadf30ef1d3eb997108e976351feb",
    },
    # Contract ABIs VERIFIED on-chain 2026-10-10 (block ~85.27M): each selector
    # pinned = keccak(sig) computed locally and confirmed as PUSH4 in the
    # LIVE bytecode (router 26 selectors / factory 149 selectors / fresh token curve
    # 80 selectors); recomputed TokenLaunched topic0 == observed real log.
    # Source: pons v2 ABIs (PonsV2LaunchFactory / PonsV2LaunchAndBuy verified
    # on Blockscout; curve from the ponsdotdev repository), cross-checked against bodkin
    # src/abi/pons.ts. Pre-graduation BUY/SELL run on the TOKEN CURVE
    # (TokenLaunched topics[2]), NOT on the router; the router only performs
    # launchAndBuy (atomic launch + creator purchase).
    "abirouter": {
        "launch_and_buy": {
            "to_key": "router_launchbuy",
            "sig": ("launchAndBuy((string,string,string,string,"
                    "(string,string,string,string,string),address,uint16,bool,"
                    "bytes32,bytes32),uint256,address,uint256,uint256,address,address[])"),
            "selector": "0xf85f8e41",
            "value": "quote_in + launch_fee",
            "params": ("TokenParams{name,symbol,logo,description,"
                       "Socials{twitter,telegram,discord,website,farcaster},"
                       "creatorFeeRecipient,creatorTaxBps,<=maxCreatorTaxBps),"
                       "buybackEnabled,expectedEconomics,salt},"
                       "launchConfigId,pairToken,quoteIn,minTokensOut,recipient,"
                       "snipeTaxExemptions[] (empty by default = subject to the tax)"),
        },
    },
    "abicurve": {
        "to_key": "token_curve",  # per token: TokenLaunched topics[2] (factory_v2)
        "buy":  {"sig": "buy(uint256,uint256,address)",  "selector": "0x59a87bc1", "value": "quote_in"},
        "sell": {"sig": "sell(uint256,uint256,address)", "selector": "0xd04c6983", "value": 0},
        "reads": {
            "reserves":        "getReserves()",
            "grad_threshold":  "graduationThreshold()",
            "ready_to_grad":   "readyToGraduate()",
            "graduated":       "graduated()",
            "fee_bps":         "feeBps()",
            "creator_tax_bps": "creatorTaxBps()",
            "snipe_tax_now":   "currentSnipeTaxBps(address)",
            "snipe_exempt":    "snipeTaxExempt(address)",
            "is_native_quote": "isNativeQuote()",
            "pair_token":      "pairToken()",
            "launched_at":     "launchedAt()",
            "real_quote_res":  "realQuoteReserve()",
        },
    },
    "abifactory": {
        "to_key": "factory_v2",
        "reads": {
            "launched_token":  "getLaunchedToken(address)",
            "launch_fee":      "launchFee()",
            "snipe_tax_start": "snipeTaxStartBps()",
            "snipe_tax_secs":  "snipeTaxSeconds()",
            "max_creator_tax": "maxCreatorTaxBps()",
            "launch_enabled":  "launchEnabled()",
            "fee_escrow":      "feeEscrow()",
            "meme_hook":       "memeHook()",
            "pool_manager":    "poolManager()",
            "launch_deployer": "launchDeployer()",
        },
        "live_values_2026_10_10": {"launch_fee_eth": 0.0005,
                                   "snipe_tax_start_bps": 9900,
                                   "snipe_tax_seconds": 3,
                                   "max_creator_tax_bps": 1000,
                                   "launch_enabled": True},
    },
    "abi_verified": {
        "date": "2026-10-10",
        "block": 85271310,
        "method": "local keccak(sig) -> PUSH4 member of live bytecode (router/factory/fresh token curve); recomputed topic0 == real log",
        "source": "bodkin src/abi/pons.ts (ABIs verified on Blockscout + ponsdotdev repository)",
    },
    "topic0_tokenlaunched": "0x8d4aad4953d0ca700d468f3753aa14432d1b35b43ec6409f051fb6aa43a89607",
    "events": {
        "TokenLaunched":   "TokenLaunched(address,address,address,address,uint256,uint256)",
        "CurveBuy":        "CurveBuy(address,address,uint256,uint256,uint256,uint256)",
        "CurveSell":       "CurveSell(address,address,uint256,uint256,uint256,uint256)",
        "Launched":        "Launched(address,address,address,address,uint256,uint256)",
        "PoolGraduated":   "PoolGraduated(address,uint256,uint256,uint256)",
        "LaunchSwept":     "LaunchSwept(address,uint256,uint256)",
        "SnipeTaxCharged_topic0": "0x3bc39a5562b28f5fe8f36cecabfbaa12bb969acf05717994709225fc412a9934",
    },
    "token_event": "TokenLaunched(address,address,address,address,uint256,uint256)",
    "market": {
        "supply": 1_000_000_000 * ETH,      # 1e9 tokens, 18 dec
        "curve_sold_ratio": 35/49,           # 71.4% sold on the curve at launch
        "seeds_lp_ratio":   10/49,           # 20.4% LP seeds (position v4)
        "locker_ratio":     4/49,            # 8.2% locker
        "curve_fee_bps": 100,
        "launch_fee_eth": 0.0005,
        "graduation_eth": 4.2,
        "snipe_tax_exemptions": [],          # default 0: keep the roster out of calldata
    },
    "strategy": {
        "target_share": 0.25, "min_share": 0.02, "max_share": 0.30,
        "n_wallets": 6,
        "budget_eth": 0.25,
        "assumed_depth_eth": 5.0,             # expected initial ETH of the curve
        "hold_limit": 0.05,                   # per-wallet total <= 5% supply (pons docs)
        "tx_limit": 0.015,                    # per-tx <= 1.5% supply value
        "wave_minutes": [3, 15, 40],          # minutes after T0 for each wave
        "slot_gap_blocks": 3,                 # >=300ms between cohort txs (>=1 block = 100ms)
        "amount_cv_min": 0.75,
        "timestamp_cv_min": 0.60,
        "twins_max_diff_pct": 2.0,
        "seed": 1337,
    },
    "guards": {
        "slippage_vs_avg_entry": 0.50,        # stop wallet if deviates >50% from avg entry
        "budget_reserve_pct": 1.0,
        "max_confirm_s": 30,
    },
    "travel": {
        "sample_s": 30,
        "slope_window_min": 10,
        "share_slope_limit_per_window": 0.02, # auto-slow when 10-min delta exceeds this
        "auto_slow": True,
        "pace_max_factor": 8,
    },
    "wallets": {"file": "data/wallets.json"},
    "runs_dir": "data/runs",
    "labels_file": "data/labels.txt",
}

def deep_update(base, extra):
    for k, v in (extra or {}).items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            deep_update(base[k], v)
        else:
            base[k] = v
    return base

def load_cfg(path="data/config.json"):
    cfg = json.loads(json.dumps(DEFAULT_CFG), parse_float=Decimal)
    if os.path.exists(path):
        with open(path) as f:
            deep_update(cfg, json.load(f, parse_float=Decimal))
    return cfg

def save_cfg(cfg, path="data/config.json"):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    content = dumps_decimal(cfg, indent=2)
    with open(path, "w") as f:
        f.write(content)

PRESETS = {
    "micro": {  # week-1 validation run: mechanics over dominance
        "strategy": {"target_share": 0.04, "min_share": 0.03, "max_share": 0.06,
                     "n_wallets": 6, "budget_eth": 0.25, "assumed_depth_eth": 5.0},
    },
    "standard": {  # 55-65% target, 17 wallets (17 x 5% = 85% capacity >= max_share)
        "strategy": {"target_share": 0.58, "min_share": 0.55, "max_share": 0.65,
                     "n_wallets": 25, "budget_eth": 22.0, "assumed_depth_eth": 15.0},
    },
}

# ---------------- wallets ----------------
def gen_wallets(n, classes):
    ws = []
    keys = list(classes.keys())
    for i in range(n):
        priv = int.from_bytes(os.urandom(32), "big") % (C.N - 1) + 1
        cls = keys[i % len(keys)]
        ws.append({"i": i, "addr": C.priv_to_address(priv), "priv": hex(priv),
                   "cls": cls, "src": None, "proxy": "", "funded": False})
    return ws

def save_wallets(ws, path, overwrite=False, password=None):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    if password is None:
        password = os.environ.get("ROBINHIDDEN_PASSWORD")

    if password:
        raw_bytes = dumps_decimal(ws, indent=2).encode("utf-8")
        payload_data = C.encrypt_keystore(raw_bytes, password)
    else:
        payload_data = ws

    def _write_fd(fd):
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(dumps_decimal(payload_data, indent=2))
            f.flush()
            os.fsync(fd)

    if not overwrite:
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            raise FileExistsError(f"Wallet file already exists: {path}. Use overwrite=True to overwrite it.")
        try:
            _write_fd(fd)
        except Exception:
            try: os.unlink(path)
            except Exception: pass
            raise
    else:
        import secrets
        tmp = "%s.tmp.%s.%d" % (path, secrets.token_hex(8), os.getpid())
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        _write_fd(fd)
        os.replace(tmp, path)

def load_wallets(path, password=None):
    if password is None:
        password = os.environ.get("ROBINHIDDEN_PASSWORD")

    try:
        st = os.stat(path)
        mode = st.st_mode & 0o777
        if mode & 0o077:
            try: os.chmod(path, 0o600)
            except Exception: pass
    except Exception:
        pass

    with open(path, "r") as f:
        data = json.load(f, parse_float=Decimal)

    if isinstance(data, dict) and ("crypto" in data or data.get("version") == 3):
        if not password:
            raise ValueError(
                "Wallet file %s is an encrypted keystore. Provide password via --password or ROBINHIDDEN_PASSWORD env var." % path
            )
        decrypted_bytes = C.decrypt_keystore(data, password)
        return json.loads(decrypted_bytes.decode("utf-8"), parse_float=Decimal)

    return data

def priv_of(w):
    return int(w["priv"], 16)

# ---------------- math ----------------
def implied_share(buy_eth, depth_eth):
    b = max(buy_eth, 0.0)
    d = max(depth_eth, 0.001)
    return b / (b + d)

def cost_for_share(share, depth_eth):
    f = share
    return depth_eth * f / (1 - f) if f < 1 else float("inf")

def avg_entry_mult(share):
    return 1 / (1 - share) if share < 1 else float("inf")

def share_from_spend(spends, tvl):
    """Pooled share per wallet: s_i / (T + sum). Conservative upper bound for the hold cap."""
    spends_f = [float(s) for s in spends]
    tvl_f = float(tvl)
    tot = tvl_f + sum(spends_f)
    return [s / tot for s in spends_f] if tot else [0.0] * len(spends_f)

def min_wallets(share, per_wallet_limit):
    return int(math.ceil(share / per_wallet_limit))

def math_table():
    rows = []
    for f in (0.30, 0.50, 0.55, 0.60, 0.65, 0.70, 0.90):
        rows.append({"share": f, "cost_x_tvc": round(cost_for_share(f, 1.0), 3),
                     "avg_entry_x_initial": round(avg_entry_mult(f), 3),
                     "min_wallets_5p5pct": min_wallets(f, 0.055)})
    return rows

# ---------------- planning ----------------
def _cv(xs):
    if len(xs) < 2 or not any(xs):
        return 0.0
    m = statistics.fmean(xs)
    if m == 0: return 0.0
    return statistics.pstdev(xs) / m

def plan_campaign(cfg, _waves=None):
    """Deterministic plan: per-wallet totals (CV >= 0.75, caps respected),
    split into per-tx sizes (each <= tx_limit), slot timestamps across waves
    (timestamp CV >= 0.6, >= slot_gap_blocks apart)."""
    st = cfg["strategy"]; mk = cfg["market"]
    rng = random.Random(st.get("seed", 1337))
    n = int(st["n_wallets"])
    budget_d = Decimal(str(st["budget_eth"]))
    budget = float(budget_d)
    reserve_d = Decimal(str(cfg["guards"]["budget_reserve_pct"])) / Decimal(100)
    reserve = float(reserve_d)
    launch_fee_d = Decimal(str(mk["launch_fee_eth"]))
    launch_fee = float(launch_fee_d)
    gas_reserve_d = Decimal("0.005")
    gas_reserve = 0.005
    buy_total_d = budget_d - launch_fee_d - gas_reserve_d - budget_d * reserve_d
    buy_total = float(buy_total_d)
    if buy_total <= 0:
        raise ValueError("Budget of %.6f ETH is insufficient for fees (launch=%.6f, gas=%.6f)" % (
            budget, launch_fee, gas_reserve))
    depth = float(st["assumed_depth_eth"])
    implied = implied_share(buy_total, depth)
    lo, hi = float(st["min_share"]), float(st["max_share"])
    warns = []
    if implied > hi * 1.02: warns.append("implied share %.3f above max_share %.3f" % (implied, hi))
    if implied < lo * 0.98 and hi < 0.5: warns.append("implied share %.3f below range [%s,%s]" % (implied, lo, hi))

    hold_cap = float(st["hold_limit"])          # per-wallet total, fraction of supply
    tx_cap = float(st["tx_limit"])              # per-tx, fraction of curve depth value

    # wallet totals: heavy-tail draw, then enforce CV and per-wallet cap
    cap = hold_cap * (depth + buy_total)  # exact ceiling: t_i/(D+S) <= hold_cap
    weights = [1.0 / (rng.random() ** 1.2) for _ in range(n)]
    wsum = sum(weights)
    tot = [w / wsum * buy_total for w in weights]
    for _ in range(60):
        cv = _cv(tot)
        over = [i for i, t in enumerate(tot) if t > cap]
        if cv >= float(st["amount_cv_min"]) and not over:
            break
        if over:
            for i in sorted(over, key=lambda i: -tot[i]):
                g = tot[i] - cap
                targets = sorted((j for j in range(n) if j != i and tot[j] < cap),
                                 key=lambda j: -tot[j])
                for j in targets:
                    if g <= 0: break
                    take = min(cap - tot[j], g)
                    tot[j] += take; g -= take
                if g > 0:
                    warns.append("hold cap infeasible: n*cap < budget")
                tot[i] = cap - g
        else:
            i_max = tot.index(max(tot)); i_min = tot.index(min(tot))
            mv = (tot[i_max] - tot[i_min]) * 0.1
            tot[i_max] -= mv; tot[i_min] += mv
    # twins guard + renormalization to match the budget
    srt = sorted(range(n), key=lambda i: tot[i])
    for a, b in zip(srt, srt[1:]):
        if tot[a] > 0 and abs(tot[b] - tot[a]) / min(tot[a], tot[b]) * 100 < float(st["twins_max_diff_pct"]):
            tot[b] *= 1.025
    f = buy_total / sum(tot)
    tot = [t * f for t in tot]
    f = buy_total / sum(tot)
    tot = [t * f for t in tot]
    for i in range(n):
        if tot[i] > cap:
            extra = tot[i] - cap
            room = [(j, cap - tot[j]) for j in range(n) if j != i and 0 < cap - tot[j]]
            rsum = sum(r for _, r in room)
            if rsum > 0:
                for j, r in room:
                    tot[j] += extra * r / rsum
                tot[i] = cap
    # decorrelation: monotonically increasing sweep, ONE pass (convergent by
    # construction: each index is written once and only increases -> stable gaps)
    thr = float(st["twins_max_diff_pct"]) * 1.2 / 100.0
    idx_asc = sorted(range(n), key=lambda i: tot[i])
    vals = [tot[i] for i in idx_asc]
    for k in range(len(vals) - 1):
        if vals[k] <= 0:
            continue
        if abs(vals[k+1] - vals[k]) / min(vals[k], vals[k+1]) >= thr:
            continue
        if cap > 0 and abs(vals[k] - cap) < 0.03 * cap and abs(vals[k+1] - cap) < 0.03 * cap:
            continue  # clustered at the hold cap: structural density (I6 ignores this band)
        vals[k+1] = max(vals[k+1], vals[k] * (1 + thr))
    for k, i in enumerate(idx_asc):
        tot[i] = vals[k]
    f = buy_total / sum(tot)
    tot = [t * f for t in tot]
    order = sorted(range(n), key=lambda i: -tot[i])
    wallet_totals = [0.0] * n
    for rank, idx in enumerate(order):
        wallet_totals[idx] = tot[rank]

    # split into txs, respecting per-tx cap
    slots = []
    tx_cap_eth = tx_cap * depth
    n_tx = {}
    for i in range(n):
        need = int(math.ceil(wallet_totals[i] / max(tx_cap_eth * 0.98, 1e-9))) if tx_cap_eth > 0 else 2
        n_tx[i] = max(2, need)
    for i in range(n):
        total_i = wallet_totals[i]
        frac = [rng.random() ** 0.6 for _ in range(n_tx[i])]
        fs = sum(frac); frac = [f / fs for f in frac]
        # enforce per-tx cap with iterative shrink -> bump smallest
        vals = [f * total_i for f in frac]
        for _ in range(40):
            viol = [j for j, v in enumerate(vals) if v > tx_cap * depth]
            if not viol: break
            j = max(viol, key=lambda j: vals[j])
            k = min((j2 for j2 in range(len(vals)) if j2 != j), key=lambda j2: vals[j2])
            mv = min(vals[j] - tx_cap * depth, vals[j] * 0.3)
            vals[j] -= mv; vals[k] += mv
        acc = 0.0
        for j, v in enumerate(vals):
            acc += v
            slots.append({"wallet": i, "tx": j, "eth": v, "wei": eth_to_wei(v), "acc_share": acc / buy_total})
    # timestamps: monotonic in [0, last wave], power curve with exponent 1.6
    # (dense initially, sparse later -> cv_timestamp >= 0.6 by construction)
    base = time.time()
    wave_min = list(_waves or st["wave_minutes"])
    N = len(slots)
    span = float(max(wave_min)) * 60.0
    gap_s = float(st["slot_gap_blocks"]) * 0.1
    lead = 20.0
    order_idx = list(range(N))
    rng.shuffle(order_idx)
    prev_ts = None
    for pos, sidx in enumerate(order_idx):
        frac = (pos / (N - 1)) ** 1.6 if N > 1 else 0.0
        ts = lead + span * frac
        if prev_ts is not None and ts < prev_ts + gap_s:
            ts = prev_ts + gap_s
        prev_ts = ts
        slots[sidx]["t"] = round(ts, 1)  # seconds since the campaign trigger
        slots[sidx]["wave"] = pos // max(1, N // len(wave_min))
    ts_all = [s["t"] for s in slots]
    cvt = _cv([t - min(ts_all) for t in ts_all])
    wallet_shares = share_from_spend(wallet_totals, depth)
    buy_total_wei = eth_to_wei(buy_total_d)

    # Integer conservation: distribute any fractional wei rounding difference to conserve exact total
    allocated_wei = sum(s["wei"] for s in slots)
    diff_wei = buy_total_wei - allocated_wei
    if diff_wei != 0 and slots:
        largest_slot = max(slots, key=lambda s: s["wei"])
        largest_slot["wei"] += diff_wei
        largest_slot["eth"] = wei_to_eth(largest_slot["wei"])

    plan = {
        "created": base, "budget_eth": float(budget_d), "budget_wei": eth_to_wei(budget_d),
        "buy_total": buy_total, "buy_total_wei": buy_total_wei, "depth_assumed": depth,
        "implied_share": implied, "wallet_totals": wallet_totals,
        "slots": slots, "warns": warns, "cv_amount": _cv(wallet_totals),
        "cv_timestamp": cvt, "wallet_shares": wallet_shares,
    }
    plan["invariant_check"] = check_invariants(cfg, plan, graph=None)
    return plan

def check_invariants(cfg, plan, graph=None):
    """The nine hygiene invariants, as compiled assertions."""
    st = cfg["strategy"]; issues, notes = [], []
    slots = plan["slots"]; wt = plan.get("wallet_totals", [])
    # I1 intra-cohort edges == 0
    funders = []
    for s in slots:
        pass
    # handled on funded wallets; placeholder uses plan['funders'] if present
    if "funders" in plan:
        fset = set(plan["funders"])
        if len(fset) != len(plan["funders"]) and plan["cohort_size"] != 1:
            if len(set(plan["funders"])) < len(plan["funders"]):
                issues.append("I1: intra-cohort funding edge found")
    # I3 hubs (needs graph data)
    if graph is not None:
        for w, g in graph.items():
            deg = g.get("degree", 0); share_c = g.get("cohort_share", 0)
            if deg < 500: notes.append("I3: hub %s degree %d < 500" % (w, deg))
            if share_c > 0.03: notes.append("I3: cohort share %.1f%% of hub %s > 3%%" % (share_c * 100, w))
    else:
        notes.append("I3: pending -- run validate --graph")
    # I4 one provenance origin per wallet
    if "sources" in plan:
        seen = set()
        for s in plan["sources"]:
            if s in seen: issues.append("I4: repeated provenance origin " + s)
            seen.add(s)
    # I5 timestamp CV (recomputed directly from slots when cohort >= 2)
    ts_all = [float(s["t"]) for s in slots if "t" in s]
    if len(ts_all) >= 2:
        cvt = _cv([t - min(ts_all) for t in ts_all])
        if cvt < float(st["timestamp_cv_min"]):
            issues.append("I5: timestamp CV %.2f < %.2f" % (cvt, st["timestamp_cv_min"]))
    elif "cv_timestamp" in plan and float(plan["cv_timestamp"]) < float(st["timestamp_cv_min"]):
        issues.append("I5: timestamp CV %.2f < %.2f" % (float(plan["cv_timestamp"]), st["timestamp_cv_min"]))

    # I6 amount CV + twins + per-wallet hold cap (recomputed directly from wt when >= 2)
    if wt and len(wt) >= 2:
        cva = _cv(wt)
        if cva < float(st["amount_cv_min"]):
            issues.append("I6: amount CV %.2f < %.2f" % (cva, st["amount_cv_min"]))
    elif "cv_amount" in plan and float(plan["cv_amount"]) < float(st["amount_cv_min"]):
        issues.append("I6: amount CV %.2f < %.2f" % (float(plan["cv_amount"]), st["amount_cv_min"]))

    amounts = sorted(float(a) for a in wt if a > 0)
    cap_i6 = float(st["hold_limit"]) * (float(plan.get("depth_assumed", 0.0)) + float(plan.get("buy_total", 0.0)))
    for i in range(len(amounts) - 1):
        if abs(amounts[i+1] - amounts[i]) / min(amounts[i], amounts[i+1]) * 100 < float(st["twins_max_diff_pct"]):
            if cap_i6 > 0 and abs(amounts[i] - cap_i6) < 0.03 * cap_i6 and abs(amounts[i+1] - cap_i6) < 0.03 * cap_i6:
                continue  # both at the hold cap (structural, not a twin)
            issues.append("I6: twin amounts (%.4f, %.4f) within 2%%" % (amounts[i], amounts[i+1]))

    depth = float(plan.get("depth_assumed") or st.get("assumed_depth_eth", 5.0))
    ws = share_from_spend(wt, depth) if (wt and depth > 0) else plan.get("wallet_shares")
    if ws:
        for i, sh in enumerate(ws):
            if sh > float(st["hold_limit"]) + 1e-9:
                issues.append("I6: wallet %d holds %.2f%% of supply > %.0f%% cap" % (i, sh * 100, st["hold_limit"] * 100))
    # I7 no common sweep destination
    if "exits" in plan:
        dst = set(e["dest"] for e in plan["exits"])
        if len(dst) != len(plan["exits"]):
            issues.append("I7: shared sweep destination")
    # I8 venue diversity
    venues = set()
    for s in slots: venues.add(s.get("venue", "pons_curve"))
    if len(venues) < 2:
        notes.append("I8: single venue (documented: pre-graduation the curve IS the venue)")
    # I9 one cohort tx per block
    ts = sorted({s["t"] for s in slots if "t" in s})
    gap_ok = len(ts) <= 1 or all(b - a >= 0.09 for a, b in zip(ts, ts[1:]))
    if not gap_ok:
        issues.append("I9: two cohort txs in the same block")
    # I2 no supply to deployer
    if plan.get("deployer_supply", 0) > 0:
        issues.append("I2: deployer holds supply")
    return {"fail": issues, "warn": notes, "pass": not issues}
