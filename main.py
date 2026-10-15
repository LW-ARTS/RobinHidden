#!/usr/bin/env python3
"""ROBINHIDDEN v3.1 — CLI (stdlib only, Python >= 3.8).

Commands:
  selftest [--live]   full test suite (offline, or including mainnet 4663)
  status [--live]     chain health and contract bytecode baseline
  gen --n N           generate N EOA wallets (class A/B/C) in data/wallets.json
  plan                plan the campaign (micro/standard presets, CLI overrides)
  verify PLAN.json    replan with the same seed and compare byte for byte
  doctor              preflight check: verify RPC, curve, snipe tax, and wallet balances
  run                 execute the campaign (dry-run by default; --send signs and broadcasts)
  sync                list named selectors from router/factory bytecode
"""
import argparse, collections, json, math, os, secrets, sys, time
from decimal import Decimal
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from rh import model as M, rpc as R, crypto as C
from rh import exec as X
from rh import nonce as N

CFG = os.path.join(HERE, "data/config.json")

def _dump_json(obj, f, indent=2):
    content = M.dumps_decimal(obj, indent=indent)
    f.write(content)

def inv_report(r):
    if isinstance(r, dict):
        issues = r.get("issues") or r.get("fail") or []
        notes = r.get("warn") or r.get("warns") or r.get("notes") or []
        return list(issues), list(notes)
    try:
        return list(r[0]), list(r[1])
    except Exception:
        return [], []

def cmd_selftest(a):
    sys.argv = [a.cmd] + (["--live"] if a.live else [])
    import selftest
    selftest.main()

def cmd_status(a):
    cfg = M.load_cfg(CFG)
    if not a.live:
        ch = cfg["chain"]
        print("chain   : %d  %s" % (ch["id"], " ".join(ch["rpc"])))
        print("explorer: %s" % ch["explorer"])
        print("baseline: %d contracts pinned (%s)" % (len(R.BASELINE), R.BASELINE_DATE))
        w_path = os.path.join(HERE, "data/wallets.json")
        if os.path.exists(w_path):
            try:
                with open(w_path) as wf:
                    w_data = json.load(wf, parse_float=Decimal)
                if isinstance(w_data, dict) and ("crypto" in w_data or w_data.get("version") == 3):
                    print("custody : %s [ENCRYPTED KEYSTORE V3]" % w_path)
                elif isinstance(w_data, list):
                    print("custody : %s [PLAINTEXT KEYS: %d wallets - MIGRATION TO ENCRYPTED KEYSTORE REQUIRED FOR PRODUCTION (run: python3 main.py wallet encrypt --in data/wallets.json --out data/wallets.json --password ...)]" % (w_path, len(w_data)))
            except Exception:
                pass
        print("(without --live: local configuration only; use --live to check bytecode)")
        return
    c = R.Rpc(cfg)
    st = c.stats
    print("chain_id : %d" % c.chain_id())
    print("block    : %d   gasPrice=%d wei  baseFee=%d wei (L2)" % (
        c.block_number(), c.gas_price(), c.base_fee()))
    print("rpc      : calls=%d failovers=%d lag_max=%.0f ms" % (
        st["calls"], st["failovers"], st["max_lag_seen"]))
    out, changed = R.check_update(cfg)
    for r_ in out:
        print("BASELINE %-16s live=%s %s" % (r_["name"], (r_["live"] or "?")[:18], r_["status"]))
    if changed:
        print("!! CHANGED since baseline: %s" % ", ".join(changed))

def cmd_gen(a):
    classes = {x.strip().upper(): 1 for x in a.classes.split(",") if x.strip()}
    ws = M.gen_wallets(a.n, classes)
    out = a.out if os.path.isabs(a.out) else os.path.join(HERE, a.out)
    force = getattr(a, "force", False)
    password = getattr(a, "password", None)
    try:
        M.save_wallets(ws, out, overwrite=force, password=password)
    except FileExistsError as e:
        print("ERROR:", e)
        print("To overwrite existing wallets with newly generated keys, pass --force.")
        print("NOTE: To encrypt existing wallets in place without generating new keys, use 'robinhidden wallet encrypt' or 'robinhidden encrypt'.")
        sys.exit(1)
    for w in ws:
        print("%02d [%s] %s" % (w["i"], w["cls"], w["addr"]))
    print("saved: %s (%d wallets, chmod 600%s)" % (out, len(ws), ", encrypted" if (password or os.environ.get("ROBINHIDDEN_PASSWORD")) else ""))

def _plan_cfg(a):
    cfg = M.load_cfg(CFG)
    if a.preset:
        M.deep_update(cfg, M.PRESETS[a.preset])
    st = cfg["strategy"]
    for k, v in (("target_share", a.target), ("budget_eth", a.budget),
                 ("assumed_depth_eth", a.depth), ("n_wallets", a.wallets), ("seed", a.seed)):
        if v is not None:
            st[k] = v
    if getattr(a, "minshare", None) is not None:
        st["min_share"] = a.minshare
    if getattr(a, "maxshare", None) is not None:
        st["max_share"] = a.maxshare
    return cfg

def cmd_plan(a):
    cfg = _plan_cfg(a)
    p = M.plan_campaign(cfg)
    st = cfg["strategy"]
    iss, wrn = inv_report(p.get("invariant_check"))
    print("ROBINHIDDEN plan  (preset=%s seed=%s)" % (a.preset or "-", st.get("seed")))
    print("  target %.1f%%   implied %.2f%%   [range %.1f%% - %.1f%%]" % (
        st["target_share"] * 100, p["implied_share"] * 100,
        st["min_share"] * 100, st["max_share"] * 100))
    print("  wallets %d   budget %.2f ETH   assumed depth %.2f ETH   buy total %.4f ETH" % (
        st["n_wallets"], st["budget_eth"], p["depth_assumed"], p["buy_total"]))
    print("  cv_amount %.3f (min %.2f)   cv_timestamp %.3f (min %.2f)" % (
        p["cv_amount"], st["amount_cv_min"], p["cv_timestamp"], st["timestamp_cv_min"]))
    mx = max(p["wallet_shares"]) * 100 if p.get("wallet_shares") else 0.0
    print("  maximum share per wallet %.3f%% (cap %.1f%%)   slots %d" % (
        mx, st["hold_limit"] * 100, len(p["slots"])))
    print("  invariants I1-I9: %s" % ("ok" if not iss else iss))
    if wrn:
        print("  warns: %s" % wrn)
    top = sorted(enumerate(p["wallet_totals"]), key=lambda t: -t[1])[:8]
    print("  largest purchases:")
    for i, v in top:
        print("    w%-3d %8.4f ETH   %5.2f%% of supply" % (i, v, p["wallet_shares"][i] * 100))
    out = a.out or os.path.join(HERE, "data/runs/plan-%s.json" % time.strftime("%Y%m%d-%H%M%S"))
    if not os.path.isabs(out):
        out = os.path.join(HERE, out)
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w") as f:
        _dump_json({"strategy": st, "plan": p}, f, indent=2)
    print("  plan saved: %s" % out)

def cmd_verify(a):
    d = json.load(open(a.planfile), parse_float=Decimal)
    cfg = M.load_cfg(CFG)
    M.deep_update(cfg, d)
    p2 = M.plan_campaign(cfg)
    p1 = d["plan"]
    tot1 = p1.get("wallet_totals", [])
    tot2 = p2.get("wallet_totals", [])
    same_tot = len(tot1) == len(tot2) and len(tot1) > 0 and all(abs(float(x) - float(y)) < 1e-9 for x, y in zip(tot1, tot2))
    sig = lambda p: sorted((s["wallet"], round(float(s["eth"]), 9), round(float(s["t"]), 1)) for s in p.get("slots", []))
    slots1 = p1.get("slots", [])
    slots2 = p2.get("slots", [])
    same_slots = len(slots1) == len(slots2) and len(slots1) > 0 and sig(p1) == sig(p2)
    iss, wrn = inv_report(p2.get("invariant_check"))
    ok = same_tot and same_slots and not iss
    print("verify %s:" % a.planfile)
    print("  identical totals = %s" % same_tot)
    print("  identical slots  = %s" % same_slots)
    print("  invariants      = %s" % ("ok" if not iss else iss))
    sys.exit(0 if ok else 1)

def cmd_doctor(a):
    cfg = M.load_cfg(CFG)
    c = R.Rpc(cfg)
    print("=== ROBINHIDDEN DOCTOR (Production Preflight) ===")
    rpc_ok = False
    bf = 10 ** 7

    # 1. RPC & Chain
    try:
        t0 = time.time()
        cid = c.chain_id()
        rpc_ms = (time.time() - t0) * 1000.0
        bn = c.block_number()
        bf = X.base_fee(c)
        expected_cid = int(cfg["chain"]["id"])
        if cid == expected_cid:
            print("  [OK] RPC Online: chainId=%d, block=%d, baseFee=%.3f gwei (ping %.0fms)" % (cid, bn, bf / 1e9, rpc_ms))
            rpc_ok = True
        else:
            print("  [ERROR] RPC connected to the wrong network: chainId=%d != expected %d" % (cid, expected_cid))
    except Exception as e:
        print("  [FAILURE] RPC connection failed: %r" % e)

    # 2. Token & Curve
    curve = a.curve
    st_bps = None
    curve_ok = False
    if a.token or a.curve:
        try:
            curve = curve or X.find_curve(c, cfg, a.token)
            curve_code = c.code(curve)
            if len(curve_code) == 0:
                print("  [ERROR] Curve %s has no deployed bytecode!" % curve)
            else:
                print("  [OK] Curve resolved for token %s: %s" % (getattr(a, "token", "")[:10], curve))
                res = c.call("eth_call", [{"to": curve, "data": "0x" + C.sel("getReserves()").hex()}, "latest"])
                if not res or not isinstance(res, str) or not res.startswith("0x") or len(res) < 130:
                    print("  [FAILURE] Invalid or null getReserves() reserve response: %r" % res)
                    curve_ok = False
                else:
                    qr_raw = int(res[2:66], 16); tr_raw = int(res[66:130], 16)
                    if qr_raw <= 0 or tr_raw <= 0:
                        print("  [FAILURE] Curve reserves are zero or negative: quote=%d token=%d" % (qr_raw, tr_raw))
                        curve_ok = False
                    else:
                        qr = qr_raw / 1e18; tr = tr_raw / 1e18
                        print("  [OK] Curve reserves: quote=%.4f ETH, token=%.2f" % (qr, tr))
                        cst = c.call("eth_call", [{"to": curve, "data": "0x" + C.sel("currentSnipeTaxBps(address)").hex() + C.enc_val("address", "0x0000000000000000000000000000000000000001").hex()}, "latest"])
                        if not cst or not isinstance(cst, str) or not cst.startswith("0x") or len(cst) < 3:
                            print("  [FAILURE] Invalid or null snipe tax response: %r" % cst)
                            curve_ok = False
                            st_bps = None
                        else:
                            st_bps = int(cst, 16)
                            if st_bps == 0:
                                print("  [OK] Snipe tax inactive: 0 bps (ready to buy)")
                                curve_ok = True
                            else:
                                print("  [CRITICAL WARNING] Snipe tax active: %d bps (%.1f%% tax!)" % (st_bps, st_bps / 100.0))
                                curve_ok = False
        except Exception as e:
            print("  [FAILURE] Could not query the curve/token: %r" % e)
            curve_ok = False
            st_bps = None
    else:
        curve_ok = False

    # 3. Plan and Wallets
    missing_balances = 0
    if a.plan:
        d = json.load(open(a.plan), parse_float=Decimal)
        p = d["plan"]
        ws = M.load_wallets(a.wallets, password=getattr(a, "password", None))
        w_map = {w["i"]: w for w in ws}
        tot = p.get("wallet_totals", [])
        slots = p.get("slots", [])

        print("\n--- Wallet Funding Check ---")
        maxfee = max(bf * 2 + 10 ** 6, 5 * 10 ** 7)
        gas_eth = (a.gas * maxfee) / 1e18

        needed = {}
        for s in slots:
            i = s["wallet"]
            needed[i] = needed.get(i, 0.0) + float(s["eth"]) + gas_eth
        if not needed:
            for i, v in enumerate(tot):
                needed[i] = float(v) + gas_eth

        total_req = sum(needed.values())
        total_bal = 0.0

        for i in sorted(needed.keys()):
            w = w_map.get(i)
            if not w:
                print("  [ERROR] Wallet %d not found in %s" % (i, a.wallets))
                missing_balances += 1
                continue
            bal = 0.0
            if rpc_ok:
                try:
                    bal = c.balance(w["addr"]) / 1e18
                except Exception:
                    pass
            total_bal += bal
            diff = bal - needed[i]
            st_txt = "OK" if (rpc_ok and diff >= 0) else ("OFFLINE (SHORT BY %.6f ETH)" % needed[i] if not rpc_ok else "SHORT BY %.6f ETH" % (-diff))
            if diff < 0 or not rpc_ok:
                missing_balances += 1
            print("  w%02d %s: balance=%.6f ETH | required=%.6f ETH [%s]" % (i, w["addr"][:10], bal, needed[i], st_txt))

        print("\nBalance Summary: wallet total=%.4f ETH | total required=%.4f ETH" % (total_bal, total_req))
        ready = rpc_ok and curve_ok and missing_balances == 0 and st_bps == 0
        if ready:
            print(">>> STATUS: ALL WALLETS FUNDED AND CONTRACT READY FOR EXECUTION! <<<")
        else:
            print(">>> STATUS: ISSUES FOUND (RPC, CURVE, TAX, OR BALANCE). NOT READY FOR EXECUTION. <<<")
            sys.exit(1)

def cmd_run(a):
    cfg = M.load_cfg(CFG)
    d = json.load(open(a.plan), parse_float=Decimal)
    p = d["plan"]
    ws = M.load_wallets(a.wallets, password=getattr(a, "password", None))
    w_map = {w["i"]: w for w in ws}
    c = R.Rpc(cfg)

    # 1. Plan Invariant and Mathematical Consistency Validation
    inv = p.get("invariant_check")
    if not isinstance(inv, dict) or inv.get("pass") is not True:
        if not getattr(a, "dangerously_ignore_invariants", False):
            raise ValueError("The supplied plan has no approved invariant check (invariant_check.pass must be True). Aborting execution.")

    # Invariants must not contain contradictory declared failures
    inv_failures = (inv.get("fail") or []) + (inv.get("issues") or [])
    if inv_failures and not getattr(a, "dangerously_ignore_invariants", False):
        raise ValueError("The supplied plan contains invariant failures recorded in the JSON: %r" % inv_failures)

    # Strict independent recomputation of mathematical invariants
    computed_inv = M.check_invariants(cfg, p)
    if not computed_inv.get("pass", False) and not getattr(a, "dangerously_ignore_invariants", False):
        raise ValueError("The plan failed independent invariant recomputation: %r" % computed_inv.get("fail"))

    slots_raw = p.get("slots", [])
    if slots_raw:
        slots = sorted(slots_raw, key=lambda s: float(s.get("t", 0.0)))
    else:
        tot = p.get("wallet_totals", [])
        slots = [{"wallet": i, "tx": 0, "eth": tot[i], "t": 0.0} for i in range(len(tot))]

    # Slot sanity validation
    for s in slots:
        val_eth = float(s.get("eth", 0.0))
        ts_val = float(s.get("t", 0.0))
        if not math.isfinite(val_eth) or val_eth <= 0:
            raise ValueError("Invalid slot amount (nonpositive or infinite): %r" % val_eth)
        if not math.isfinite(ts_val) or ts_val < 0:
            raise ValueError("Invalid slot timestamp: %r" % ts_val)

    # Strict consistency validation between slots and wallet_totals
    wallet_slots_sum = {}
    for s in slots:
        w_idx = s["wallet"]
        wallet_slots_sum[w_idx] = wallet_slots_sum.get(w_idx, 0.0) + float(s["eth"])

    wt = p.get("wallet_totals", [])
    if wt:
        if len(wt) < len(wallet_slots_sum):
            raise ValueError("Inconsistency: wallet_totals declares %d wallets, but slots use %d wallets!" % (len(wt), len(wallet_slots_sum)))
        for idx, expected_tot in enumerate(wt):
            actual_tot = wallet_slots_sum.get(idx, 0.0)
            if abs(actual_tot - float(expected_tot)) > 1e-9:
                raise ValueError("Plan inconsistency: wallet %d totals %.6f ETH across slots, but declares %.6f ETH in wallet_totals!" % (idx, actual_tot, float(expected_tot)))

    # Wallet presence validation
    missing_wallets = [s["wallet"] for s in slots if s["wallet"] not in w_map]
    if missing_wallets:
        raise ValueError("Plan wallets not found in file %s: %s" % (a.wallets, set(missing_wallets)))

    budget_raw = d.get("strategy", {}).get("budget_eth")
    if budget_raw is None or not isinstance(budget_raw, (int, float, Decimal)) or not math.isfinite(float(budget_raw)) or float(budget_raw) <= 0:
        raise ValueError("Declared strategy budget (strategy.budget_eth) is missing, invalid, or nonfinite: %r" % budget_raw)

    budget_wei = d.get("strategy", {}).get("budget_wei") or M.eth_to_wei(str(budget_raw))

    # Slippage validation
    if not (0 <= a.slip_bps <= 5000):
        raise ValueError("slip_bps outside the safe range (0 to 5000 bps): %d" % a.slip_bps)

    # BaseFee and MaxFee (required to budget the maximum gas cost per order)
    try:
        bf = X.base_fee(c)
    except Exception as e:
        if not a.send:
            print("  [INFO] RPC unavailable (%s). Using a simulated baseFee (0.01 gwei) for dry-run." % repr(e)[:80])
            bf = 10 ** 7
        else:
            raise

    maxfee = max(bf * 2 + 10 ** 6, 5 * 10 ** 7)
    prio = min(10 ** 6, max(1, bf // 10))

    # Strict budget validation in WEI (including the maximum gas cost per order)
    total_value_wei = sum(s.get("wei") or M.eth_to_wei(str(s["eth"])) for s in slots)
    max_gas_per_tx_wei = int(a.gas) * maxfee
    total_max_gas_wei = len(slots) * max_gas_per_tx_wei
    total_authorized_commitment_wei = total_value_wei + total_max_gas_wei

    if total_authorized_commitment_wei > budget_wei and not getattr(a, "force", False):
        raise ValueError(
            "Maximum authorized spending (purchases: %.6f ETH + gas ceiling: %.6f ETH = %.6f ETH) "
            "exceeds the declared budget (%.6f ETH)!" % (
                total_value_wei / 1e18, total_max_gas_wei / 1e18,
                total_authorized_commitment_wei / 1e18, budget_wei / 1e18
            )
        )

    # 2. Network, Destination, and Baseline Authentication
    if a.send:
        actual_cid = c.chain_id()
        expected_cid = int(cfg["chain"]["id"])
        if actual_cid != expected_cid:
            raise RuntimeError("RPC network mismatch: connected to chainId %d, but configuration requires %d." % (actual_cid, expected_cid))

    # Contract baseline inspection
    baseline_rows, changed_contracts = R.check_update(cfg)
    no_code = [r["name"] for r in baseline_rows if r["status"] == "NO_CODE"]
    if no_code:
        raise RuntimeError("Critical failure: essential baseline contracts have no bytecode: %s" % no_code)
    changed = [r["name"] for r in baseline_rows if r["status"] == "CHANGED"]
    if changed:
        raise RuntimeError("Critical failure: baseline contracts changed or mismatched: %s" % changed)
    pending_bl = [r["name"] for r in baseline_rows if r["status"] == "PENDING_BASELINE"]
    if pending_bl and (a.send or getattr(a, "sign", False)) and not getattr(a, "allow_unverified_baseline", False):
        raise RuntimeError("Critical failure: broadcast preparation blocked by a pending contract baseline (__PENDING__): %s. Use --allow-unverified-baseline to proceed with explicit acknowledgment." % pending_bl)

    # Token -> Curve resolution and binding validation
    curve = a.curve
    if a.token:
        resolved_curve = None
        try:
            resolved_curve = X.find_curve(c, cfg, a.token)
        except Exception as e:
            if not curve:
                raise RuntimeError("Failed to resolve the curve for token %s: %r" % (a.token, e))
            if (a.send or getattr(a, "sign", False)) and not getattr(a, "allow_unverified_curve", False):
                raise RuntimeError("Critical failure: on-chain binding between token %s and curve (%s) is not verified through the Factory: %r. Use --allow-unverified-curve to proceed with explicit acknowledgment." % (a.token, curve, e))
            print("  [WARNING] Could not resolve the curve through the Factory for token %s: %r" % (a.token, e))

        if resolved_curve:
            if curve and curve.lower() != resolved_curve.lower():
                raise ValueError("The supplied curve (%s) does not match the official curve for token %s resolved through the Factory (%s)!" % (curve, a.token, resolved_curve))
            curve = resolved_curve
        elif not curve:
            raise RuntimeError("Critical failure: curve not resolved for token %s." % a.token)
        elif (a.send or getattr(a, "sign", False)) and not getattr(a, "allow_unverified_curve", False):
            raise RuntimeError("Critical failure: on-chain binding between token %s and curve (%s) is not verified through the Factory. Use --allow-unverified-curve to proceed with explicit acknowledgment." % (a.token, curve))
    elif not curve:
        raise ValueError("Provide --token or --curve for execution.")
    elif (a.send or getattr(a, "sign", False)) and not getattr(a, "allow_unverified_curve", False):
        raise RuntimeError("Critical failure: execution without --token does not verify the binding of curve (%s) through the Factory. Use --allow-unverified-curve to proceed with explicit acknowledgment." % curve)

    if getattr(a, "allow_unverified_curve", False):
        print("  ⚠️ [SECURITY WARNING] Executing with curve (%s) without a verified Factory binding because --allow-unverified-curve was provided!" % curve)

    curve_code = c.code(curve)
    if not curve_code or len(curve_code) == 0:
        raise RuntimeError("Curve destination %s has no deployed bytecode on the network! Aborting." % curve)
    if C.sel("buy(uint256,uint256,address)") not in curve_code:
        raise RuntimeError("Destination bytecode at %s does not contain the Pons curve buy(...) selector!" % curve)

    print("ROBINHIDDEN run  (dry-run %s)" % ("No" if a.send else "yes"))
    print("  token %s  curve %s" % (getattr(a, "token", "")[:10], curve[:10]))
    print("  baseFee %.3f gwei  maxFee %.3f gwei  gas %d  slip %d bps" % (bf / 1e9, maxfee / 1e9, a.gas, a.slip_bps))

    # 3. Snipe Tax Check (Fail-Closed)
    try:
        sample_addr = ws[0]["addr"] if ws else "0x0000000000000000000000000000000000000001"
        cst_call = "0x" + C.sel("currentSnipeTaxBps(address)").hex() + C.enc_val("address", sample_addr).hex()
        cst_res = c.call("eth_call", [{"to": curve, "data": cst_call}, "latest"])
        if not cst_res or not isinstance(cst_res, str) or not cst_res.startswith("0x") or len(cst_res) < 3:
            raise RuntimeError("Critical failure: undefined or null snipe tax response from the curve (%r)" % cst_res)
        st_bps = int(cst_res, 16)
        if st_bps > 0:
            print("  ⚠️ [SECURITY ALERT] Snipe tax active on the curve: %d bps (%.1f%% tax!)" % (st_bps, st_bps / 100.0))
            if a.send and not getattr(a, "force", False):
                print("  Broadcast ABORTED to protect funds. Wait for the tax to decay or use --force to override.")
                sys.exit(1)
    except Exception as e:
        if a.send:
            raise RuntimeError("Critical failure while querying snipe tax: %r" % e)
        else:
            print("  WARNING: Could not query snipe tax: %r" % repr(e)[:80])

    tmin = min((float(s.get("t", 0.0)) for s in slots), default=0.0)

    # 4. Curve Reserve Query (Fail-Closed)
    qr, tr = 0, 0
    try:
        res = c.call("eth_call", [{"to": curve, "data": "0x" + C.sel("getReserves()").hex()}, "latest"])
        if not res or not isinstance(res, str) or not res.startswith("0x") or len(res) < 130:
            raise RuntimeError("Critical failure: undefined or invalid getReserves() reserve response (%r)" % res)
        qr = int(res[2:66], 16); tr = int(res[66:130], 16)
        if qr <= 0 or tr <= 0:
            raise RuntimeError("Invalid or zero curve reserves: quote=%d token=%d" % (qr, tr))
    except Exception as e:
        if a.send:
            raise RuntimeError("Critical failure while querying getReserves() on the curve: %r" % e)
        else:
            print("  WARNING getReserves failed: %r" % repr(e)[:80])

    # 5. Nonces and Balances
    wallet_nonces = {}
    wallet_balances = {}
    wallet_spent_accum = {w["i"]: 0 for w in ws}
    rows, skips = [], []

    out_dir = os.path.join(HERE, "data/runs")
    os.makedirs(out_dir, exist_ok=True)
    out = os.path.join(out_dir, "run-%s-%s.json" % (time.strftime("%Y%m%d-%H%M%S"), secrets.token_hex(4)))
    out_canon = os.path.realpath(os.path.abspath(out))

    def _rollback_run_reservations(current_info=None):
        if not (a.send or getattr(a, "sign", False)):
            return
        if current_info:
            c_addr, c_nonce, c_owner = current_info
            try:
                N.release_nonce(c_addr, c_nonce,
                                state_path=os.path.join(HERE, "data/.nonces.json"),
                                lock_dir=os.path.join(HERE, "data/.locks"),
                                owner_id=c_owner)
            except Exception as err:
                print("  [ERROR] Rollback failed to release nonce %s for %s: %s" % (c_nonce, c_addr, err))
        while rows:
            r = rows.pop()
            r_owner = f"{out_canon}:slot_{r['slot']}"
            try:
                N.release_nonce(r["addr"], r["nonce"],
                                state_path=os.path.join(HERE, "data/.nonces.json"),
                                lock_dir=os.path.join(HERE, "data/.locks"),
                                owner_id=r_owner)
            except Exception as err:
                print("  [ERROR] Rollback failed to release nonce %s for %s: %s" % (r["nonce"], r["addr"], err))

    try:
        for s in slots:
            i = s["wallet"]
            if i not in w_map:
                continue
            w = w_map[i]
            addr = w["addr"]

            if addr not in wallet_nonces:
                try:
                    wallet_nonces[addr] = int(c.call("eth_getTransactionCount", [addr, "pending"]), 16)
                    wallet_balances[addr] = int(c.call("eth_getBalance", [addr, "latest"]), 16)
                except Exception:
                    wallet_nonces[addr] = 0
                    wallet_balances[addr] = (100 * X.ETH) if not a.send else 0

            value = s.get("wei") or M.eth_to_wei(s["eth"])
            need = value + int(a.gas) * maxfee
            wallet_spent_accum[i] += need

            bal = wallet_balances[addr]
            if a.send and bal < wallet_spent_accum[i]:
                skips.append({"wallet": i, "tx": s.get("tx", 0), "addr": addr, "bal": bal, "need": wallet_spent_accum[i]})
                print("  w%02d [tx%d] %s SKIP insufficient balance (bal %.6f ETH < need %.6f ETH)" % (
                    i, s.get("tx", 0), addr[:10], bal / 1e18, wallet_spent_accum[i] / 1e18))
                continue

            min_out = 0
            if qr > 0 and tr > 0 and value > 0:
                est = tr * value / (qr + value)
                min_out = int(est * (10000 - a.slip_bps) / 10000) if a.slip_bps > 0 else 0

            if a.send and min_out == 0 and value > 0 and not getattr(a, "allow_zero_slippage", False):
                raise RuntimeError("min_out calculated as 0 for w%02d. Aborting broadcast without slippage protection." % i)

            slot_idx = len(rows)
            run_owner = f"{out_canon}:slot_{slot_idx}"
            reserved_info = None
            if a.send or getattr(a, "sign", False):
                nonce = N.reserve_nonce(c, addr, state_path=os.path.join(HERE, "data/.nonces.json"),
                                        lock_dir=os.path.join(HERE, "data/.locks"),
                                        owner_id=run_owner)
                reserved_info = (addr, nonce, run_owner)
            else:
                nonce = wallet_nonces[addr]
                wallet_nonces[addr] += 1

            cd_data = X.calldata_buy(value, min_out, addr)

            # 6. Pre-flight Simulation, Dynamic Gas Estimation, and Signing
            delay = max(0.0, float(s.get("t", 0.0)) - tmin)
            if a.send or getattr(a, "sign", False):
                try:
                    tx_gas = X.simulate_and_estimate_buy(c, addr, curve, value, cd_data, int(a.gas))
                    txh, raw, sig, h = X.sign_tx(cfg["chain"]["id"], curve, value, cd_data, nonce,
                                                 tx_gas, maxfee, prio, int(w["priv"], 16))
                    rec = X.recover_signer(raw, cfg["chain"]["id"])
                    if rec.lower() != addr.lower():
                        raise RuntimeError("Cryptographic failure: signer (%s) != wallet (%s)" % (rec, addr))
                except Exception:
                    _rollback_run_reservations(current_info=reserved_info)
                    raise
            else:
                tx_gas = int(a.gas)
                # Pure dry-run: do not write a signed, broadcastable payload to disk
                raw = None
                txh = "0x" + "dryrun" + C.keccak256(("%s_%d_%d" % (addr, nonce, value)).encode()).hex()[:58]

            rows.append({
                "slot": slot_idx, "wallet": i, "tx": s.get("tx", 0), "addr": addr,
                "value_eth": value / 1e18, "wei": value, "min_out": min_out, "nonce": nonce,
                "delay_s": delay, "txhash": txh, "raw": raw
            })
            print("  w%02d [tx%d] %s nonce=%d value=%.6f ETH minOut=%d t+%.2fs %s" % (
                i, s.get("tx", 0), addr[:10], nonce, value / 1e18, min_out, delay, txh[:16]))

        # Save the execution plan (with chmod 0600)
        run_data = {
            "status": "prepared",
            "token": a.token, "curve": curve, "base_fee_wei": bf, "max_fee_wei": maxfee,
            "budget_wei": budget_wei, "rows": rows, "skips": skips,
            "prep_quote_reserve": qr, "prep_token_reserve": tr,
        }
        tmp_out = "%s.tmp.%s.%d" % (out, secrets.token_hex(8), os.getpid())
        fd = os.open(tmp_out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.fchmod(fd, 0o600)
        try:
            with os.fdopen(fd, "w") as f:
                _dump_json(run_data, f, indent=2)
            os.replace(tmp_out, out)
        except Exception:
            if os.path.exists(tmp_out):
                try: os.remove(tmp_out)
                except Exception: pass
            raise
        print("  %d transactions prepared | %d skipped | run saved: %s" % (len(rows), len(skips), out))
    except Exception:
        _rollback_run_reservations()
        raise

    if not a.send:
        print("  (dry-run: nothing broadcast; use --send to sign and broadcast in parallel)")
        return
    if not rows:
        print("  no funded transactions; nothing broadcast")
        sys.exit(1)

    # 7. Just-in-Time (JIT) check right before dispatch
    sample_addr = ws[0]["addr"] if ws else "0x0000000000000000000000000000000000000001"
    X.jit_check_curve_state(c, curve, sample_addr, a.slip_bps, getattr(a, "force", False), expected_reserves=(qr, tr))

    # 8. Execution, Durable Journal (fsync), and Receipt Persistence
    journal_path = out + ".journal.jsonl"
    jfd = os.open(journal_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.fchmod(jfd, 0o600)
    import threading
    jlock = threading.Lock()

    def record_event(ev_type, txh, payload):
        entry = {"ts": time.time(), "event": ev_type, "txhash": txh, "payload": payload}
        line = (json.dumps(entry) + "\n").encode("utf-8")
        with jlock:
            os.write(jfd, line)
            os.fsync(jfd)

    try:
        res = X.send_batch(c, rows, timeout_s=a.timeout, on_event=record_event)
    finally:
        os.close(jfd)

    ok = 0
    for r in rows:
        info = res.get(r["txhash"])
        st = info.get("status") if info else None
        tag = "OK " if st == "0x1" else ("REVERT" if st == "0x0" else ("PENDING" if st is None else repr(st)))
        if st == "0x1": ok += 1
        extra = ""
        if info and info.get("block"): extra = " block=%d gas=%d" % (info["block"], info.get("gasUsed", 0))
        if info and not info.get("sent"): extra = " broadcast failed: " + info.get("err", "")
        print("  w%02d [tx%d] %s %s%s" % (r["wallet"], r["tx"], r["addr"][:10], tag, extra))
        r["status"] = st
        r["receipt"] = info

    run_data["status"] = "completed" if ok == len(rows) else "partial_or_failed"
    run_data["confirmed_count"] = ok
    run_data["results"] = res
    tmp_final = "%s.tmp.res.%s.%d" % (out, secrets.token_hex(8), os.getpid())
    fd = os.open(tmp_final, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.fchmod(fd, 0o600)
    with os.fdopen(fd, "w") as f:
        _dump_json(run_data, f, indent=2)
        f.flush()
        os.fsync(fd)
    os.replace(tmp_final, out)
    print("  completed: %d/%d confirmed | receipts saved to: %s" % (ok, len(rows), out))
    if ok < len(rows):
        sys.exit(1)

def cmd_sync(a):
    cfg = M.load_cfg(CFG)
    c = R.Rpc(cfg)
    for key in ("router_launchbuy", "factory_v2"):
        addr = cfg["pons"][key]
        code = c.code(addr)
        sels = sorted({s.to_bytes(4, "big") for s in R.push4_selectors(code)}, key=lambda s: -code.count(s))
        print("== %s %s : %d distinct selectors in the bytecode" % (key, addr, len(sels)), flush=True)
        res = R.openchain_lookup([int.from_bytes(s, "big") for s in sels[:16]])
        for s in sels[:20]:
            k = "0x" + s.hex()
            nm = (res.get(k) or ["?"])[0]
            print("    %3dx %-10s %s" % (code.count(s), k, nm), flush=True)
    print("-> selectors ALREADY verified on-chain in data/config.json (block 85271310); sync lists unnamed selectors for auditing")

def cmd_resume(a):
    """Crash recovery and reconciliation: reads previous run artifact and journal,
    polls RPC and reconciles recorded journal receipts, enforces strict production guards
    (chain ID, baseline contracts, token-to-curve binding, budget, min_out), and resumes
    execution of remaining unexecuted slots without duplicate spending."""
    run_file = a.run if os.path.isabs(a.run) else os.path.join(HERE, a.run)
    if not os.path.exists(run_file):
        raise FileNotFoundError("Run artifact not found: %s" % run_file)

    with open(run_file, "r") as f:
        run_data = json.load(f, parse_float=Decimal)

    journal_file = run_file + ".journal.jsonl"
    journal_events = []
    if os.path.exists(journal_file):
        with open(journal_file, "r") as f:
            for line in f:
                line = line.strip()
                if line:
                    try: journal_events.append(json.loads(line, parse_float=Decimal))
                    except Exception: pass

    cfg = M.load_cfg(CFG)
    c = R.Rpc(cfg)

    print("=== ROBINHIDDEN CRASH RECOVERY & RECONCILIATION ===")
    print("  Run file: %s" % run_file)
    print("  Journal events recorded: %d" % len(journal_events))

    rows = run_data.get("rows", [])
    confirmed = []
    reverted = []
    pending_mempool = []
    unexecuted = []

    # Map journal events
    journal_receipts = {}
    journal_broadcasts = set()
    for e in journal_events:
        txh_e = e.get("txhash")
        if not txh_e:
            continue
        txh_norm = txh_e.lower()
        ev_type = e.get("event")
        payload = e.get("payload", {})
        if ev_type == "receipt" and isinstance(payload, dict):
            journal_receipts[txh_norm] = payload
            if payload.get("sent"):
                journal_broadcasts.add(txh_norm)
        elif ev_type in ("broadcast", "send"):
            journal_broadcasts.add(txh_norm)

    for r in rows:
        txh = r.get("txhash")
        txh_norm = txh.lower() if txh else ""
        cached_rec = r.get("receipt") or journal_receipts.get(txh_norm)

        receipt = None
        receipt_error = None
        if txh and not txh.startswith("0xdryrun"):
            try:
                receipt = c.call("eth_getTransactionReceipt", [txh])
            except Exception as err:
                receipt = None
                receipt_error = err

        # On-chain receipt takes precedence over local cached receipt.
        # If queried on-chain and RPC returns None, the transaction has no canonical on-chain
        # receipt and must NOT fall back to a stale cached success receipt!
        if txh and not txh.startswith("0xdryrun"):
            effective_rec = receipt
        else:
            effective_rec = cached_rec

        if effective_rec and effective_rec.get("status") in ("0x1", 1, True):
            r["status"] = "0x1"
            r["receipt"] = effective_rec
            confirmed.append(r)
        elif effective_rec and effective_rec.get("status") in ("0x0", 0, False):
            r["status"] = "0x0"
            r["receipt"] = effective_rec
            reverted.append(r)
        elif r.get("raw") is not None:
            # If receipt query threw an RPC error, the transaction status is ambiguous!
            if receipt_error is not None and not getattr(a, "force", False):
                raise RuntimeError("Ambiguous transaction state: RPC error querying receipt for %s: %r. Aborting resume to prevent duplicate signing." % (txh, receipt_error))
            if txh and not txh.startswith("0xdryrun") and receipt is None and cached_rec is not None:
                r["status"] = "0x0"
                r["receipt"] = {"status": "0x0", "absent": True}
            # Only classify as pending in mempool if verified broadcast in journal or on-chain
            is_broadcasted = txh_norm in journal_broadcasts
            if not is_broadcasted and txh and not txh.startswith("0xdryrun"):
                try:
                    on_chain_tx = c.call("eth_getTransactionByHash", [txh])
                    if on_chain_tx:
                        is_broadcasted = True
                except Exception as err:
                    if not getattr(a, "force", False):
                        raise RuntimeError("Ambiguous transaction state: RPC error querying transaction by hash for %s: %r. Aborting resume to prevent duplicate signing." % (txh, err))
            if is_broadcasted:
                pending_mempool.append(r)
            else:
                unexecuted.append(r)
        else:
            if receipt_error is not None and not getattr(a, "force", False):
                raise RuntimeError("Ambiguous transaction state: RPC error querying receipt for %s: %r. Aborting resume." % (txh, receipt_error))
            if txh and not txh.startswith("0xdryrun") and receipt is None and cached_rec is not None:
                r["status"] = "0x0"
                r["receipt"] = {"status": "0x0", "absent": True}
            unexecuted.append(r)

    print("\n  Summary:")
    print("    Total slots planned: %d" % len(rows))
    print("    Confirmed on-chain : %d" % len(confirmed))
    print("    Reverted           : %d" % len(reverted))
    print("    Pending in mempool : %d" % len(pending_mempool))
    print("    Unexecuted slots   : %d" % len(unexecuted))

    run_data["confirmed_count"] = len(confirmed)
    run_data["reconciled_status"] = "reconciled"
    tmp_out = "%s.tmp.rec.%s.%d" % (run_file, secrets.token_hex(6), os.getpid())
    fd = os.open(tmp_out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.fchmod(fd, 0o600)
    with os.fdopen(fd, "w") as f:
        _dump_json(run_data, f, indent=2)
        f.flush()
        os.fsync(fd)
    os.replace(tmp_out, run_file)

    if not a.send:
        print("\n  [INFO] Reconciliation completed. To broadcast remaining unexecuted slots, pass --send.")
        return

    if not unexecuted:
        print("\n  [INFO] No unexecuted slots remaining to broadcast.")
        return

    curve = run_data.get("curve")
    if not curve:
        raise ValueError("Missing curve address in run artifact: %s" % run_file)

    # --- PRODUCTION EXECUTION GUARDS ---
    # 1. Chain ID Guard
    cid = int(c.call("eth_chainId", []), 16)
    if cid != cfg["chain"]["id"]:
        raise RuntimeError("Chain ID mismatch: RPC reports %d, expected %d" % (cid, cfg["chain"]["id"]))

    # 2. Baseline Contract Code & Hash Verification
    baseline_rows, changed_contracts = R.check_update(cfg)
    no_code = [r["name"] for r in baseline_rows if r["status"] == "NO_CODE"]
    if no_code and not getattr(a, "force", False):
        raise RuntimeError("Critical failure: essential baseline contracts have no bytecode: %s. Aborting resume broadcast." % (", ".join(no_code)))
    changed = [r["name"] for r in baseline_rows if r["status"] == "CHANGED"] or changed_contracts
    if changed and not getattr(a, "force", False):
        raise RuntimeError("Critical failure: baseline contracts changed or mismatched: %s. Aborting resume broadcast." % (", ".join(set(changed))))
    pending_baseline = [r["name"] for r in baseline_rows if r["status"] == "PENDING_BASELINE"]
    if pending_baseline and not (getattr(a, "force", False) or getattr(a, "allow_unverified_baseline", False)):
        raise RuntimeError("Baseline contract hash pending for: %s. Aborting resume broadcast." % (", ".join(pending_baseline)))

    # 3. Token-to-Curve Binding Guard
    tok = run_data.get("token")
    if tok:
        try:
            discovered = X.find_curve(c, tok)
            if discovered.lower() != curve.lower():
                raise RuntimeError("Factory discovered curve (%s) != run curve (%s)" % (discovered, curve))
        except Exception as e:
            if not getattr(a, "allow_unverified_curve", False):
                raise RuntimeError("Token-to-curve binding not verified on-chain via Factory V2: %r" % e)
    else:
        if not getattr(a, "allow_unverified_curve", False):
            raise RuntimeError("Run artifact has unverified curve without token binding. Pass --allow-unverified-curve to override.")

    # BaseFee and MaxFee (required to budget the maximum gas cost per order)
    bf = X.base_fee(c)
    maxfee = run_data.get("max_fee_wei", max(bf * 2 + 10**6, 5 * 10**7))
    prio = min(10**6, max(1, bf // 10))

    # 4. Budget Invariant Guard (Enforcing purchase value + maximum gas ceiling)
    budget_wei = run_data.get("budget_wei")
    if budget_wei is None and "budget_eth" in run_data:
        budget_wei = M.eth_to_wei(str(run_data["budget_eth"]))
    if budget_wei is None and not getattr(a, "force", False):
        raise RuntimeError("Missing declared budget (budget_wei or budget_eth) in run artifact: %s. Aborting resume broadcast." % run_file)
    if budget_wei is not None:
        total_val_wei = sum(r.get("wei") or (r.get("value_wei") or M.eth_to_wei(str(r["value_eth"]))) for r in rows)
        gas_ceiling_wei = len(rows) * int(getattr(a, "gas", 200000)) * maxfee
        total_commitment_wei = total_val_wei + gas_ceiling_wei
        if total_commitment_wei > budget_wei and not getattr(a, "force", False):
            raise RuntimeError("Resume total plan cost with gas ceiling (%d wei) exceeds declared budget (%d wei)" % (total_commitment_wei, budget_wei))

    ws = M.load_wallets(a.wallets, password=getattr(a, "password", None))
    w_map = {w["i"]: w for w in ws}

    new_rows = []
    state_path = os.path.join(HERE, "data/.nonces.json")
    lock_dir = os.path.join(HERE, "data/.locks")

    # Sort unexecuted rows so rows with existing prepared nonces are processed in ascending order
    sorted_unexecuted = sorted(
        unexecuted,
        key=lambda r_: (
            0 if r_.get("nonce") is not None else 1,
            r_.get("nonce") if r_.get("nonce") is not None else 0,
            r_.get("slot", 0)
        )
    )

    for r in sorted_unexecuted:
        w = w_map[r["wallet"]]
        addr = w["addr"]
        val_wei = r.get("wei") or (r.get("value_wei") or M.eth_to_wei(str(r["value_eth"])))
        min_out = r.get("min_out", 0)

        # 5. Non-zero minimum output / slippage protection guard
        if val_wei > 0 and min_out <= 0 and not getattr(a, "allow_zero_slippage", False):
            raise RuntimeError("min_out calculated as 0 for row %d. Aborting resume broadcast without slippage protection." % r.get("slot", 0))

        # Reconcile nonce: atomically claim prepared nonce if unclaimed (or owned by this run artifact/slot)
        # or reserve next uncolliding nonce under OS-level locks
        prep_nonce = r.get("nonce")
        owner_id = f"{os.path.realpath(os.path.abspath(run_file))}:slot_{r.get('slot', 0)}"
        nonce, was_reused = N.claim_or_reserve_nonce(
            c, addr, prep_nonce=prep_nonce, state_path=state_path, lock_dir=lock_dir, owner_id=owner_id
        )

        cd_data = X.calldata_buy(val_wei, min_out, addr)
        try:
            tx_gas = X.simulate_and_estimate_buy(c, addr, curve, val_wei, cd_data, getattr(a, "gas", 200000))
        except Exception as sim_err:
            N.release_nonce(addr, nonce, state_path=state_path, lock_dir=lock_dir, owner_id=owner_id)
            raise
        txh, raw, sig, h = X.sign_tx(cfg["chain"]["id"], curve, val_wei, cd_data, nonce,
                                     tx_gas, maxfee, prio, int(w["priv"], 16))
        r["txhash"] = txh
        r["raw"] = raw
        r["nonce"] = nonce
        r["wei"] = val_wei
        new_rows.append(r)

    # Persist newly signed rows atomically before network dispatch to close crash window
    run_data["rows"] = rows
    tmp_out = "%s.tmp.prep.%s.%d" % (run_file, secrets.token_hex(6), os.getpid())
    fd = os.open(tmp_out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.fchmod(fd, 0o600)
    with os.fdopen(fd, "w") as f:
        _dump_json(run_data, f, indent=2)
        f.flush()
        os.fsync(fd)
    os.replace(tmp_out, run_file)

    def _resume_journal(ev, txh, payload):
        with open(journal_file, "a") as jf:
            jf.write(json.dumps({"event": ev, "txhash": txh, "payload": payload, "time": time.time()}) + "\n")
            jf.flush()
            os.fsync(jf.fileno())

    print("\n  Broadcasting %d unexecuted slots..." % len(new_rows))
    sample_addr = ws[0]["addr"] if ws else "0x0000000000000000000000000000000000000001"
    expected_res = None
    if "prep_quote_reserve" in run_data and "prep_token_reserve" in run_data:
        expected_res = (int(run_data["prep_quote_reserve"]), int(run_data["prep_token_reserve"]))
    else:
        try:
            c_res = c.call("eth_call", [{"to": curve, "data": "0x" + C.sel("getReserves()").hex()}, "latest"])
            if c_res and isinstance(c_res, str) and c_res.startswith("0x") and len(c_res) >= 130:
                expected_res = (int(c_res[2:66], 16), int(c_res[66:130], 16))
        except Exception:
            expected_res = None
    X.jit_check_curve_state(c, curve, sample_addr, getattr(a, "slip_bps", 300), getattr(a, "force", False), expected_reserves=expected_res)
    res = X.send_batch(c, new_rows, on_event=_resume_journal, timeout_s=getattr(a, "timeout", 60.0))
    for r in new_rows:
        info = res.get(r["txhash"])
        r["receipt"] = info
        r["status"] = info.get("status") if info else None

    # Atomic final persistence
    tmp_out = "%s.tmp.done.%s.%d" % (run_file, secrets.token_hex(6), os.getpid())
    fd = os.open(tmp_out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.fchmod(fd, 0o600)
    with os.fdopen(fd, "w") as f:
        _dump_json(run_data, f, indent=2)
        f.flush()
        os.fsync(fd)
    os.replace(tmp_out, run_file)
    print("  Resume broadcast completed and persisted.")

def cmd_encrypt(a):
    in_path = getattr(a, "wallets", None) or getattr(a, "in_file", "data/wallets.json")
    in_path = in_path if os.path.isabs(in_path) else os.path.join(HERE, in_path)
    out_path = getattr(a, "out", in_path)
    out_path = out_path if os.path.isabs(out_path) else os.path.join(HERE, out_path)
    pwd = getattr(a, "password", None) or os.environ.get("ROBINHIDDEN_PASSWORD")
    if not pwd:
        import getpass
        pwd = getpass.getpass("Enter password to encrypt wallet keystore: ")
    with open(in_path, "r") as f:
        content = f.read()
    try:
        loaded = json.loads(content)
        if isinstance(loaded, dict) and ("crypto" in loaded or loaded.get("version") == 3):
            print("File %s is already an encrypted keystore." % in_path)
            return
    except Exception:
        pass
    ks = C.encrypt_keystore(content.encode("utf-8"), pwd, kdf=getattr(a, "kdf", "scrypt"))
    tmp = "%s.tmp.enc.%s.%d" % (out_path, secrets.token_hex(6), os.getpid())
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.fchmod(fd, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(ks, f, indent=2)
        f.flush()
        os.fsync(fd)
    os.replace(tmp, out_path)
    print("Wallet successfully encrypted with Web3 Keystore v3 -> %s (chmod 0600)" % out_path)

def cmd_wallet(a):
    if a.action == "encrypt":
        return cmd_encrypt(a)

    elif a.action == "decrypt":
        in_path = a.in_file if os.path.isabs(a.in_file) else os.path.join(HERE, a.in_file)
        out_path = a.out if os.path.isabs(a.out) else os.path.join(HERE, a.out)
        pwd = getattr(a, "password", None) or os.environ.get("ROBINHIDDEN_PASSWORD")
        if not pwd:
            import getpass
            pwd = getpass.getpass("Enter password to decrypt wallet keystore: ")
        with open(in_path, "r") as f:
            data = json.load(f, parse_float=Decimal)
        decrypted = C.decrypt_keystore(data, pwd)
        tmp = "%s.tmp.dec.%s.%d" % (out_path, secrets.token_hex(6), os.getpid())
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(decrypted.decode("utf-8"))
            f.flush()
            os.fsync(fd)
        os.replace(tmp, out_path)
        print("Wallet successfully decrypted -> %s (chmod 0600)" % out_path)

def main():
    ap = argparse.ArgumentParser(prog="robinhidden", description="invisible bundle on Robinhood Chain / Pons")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("selftest"); sp.add_argument("--live", action="store_true"); sp.set_defaults(fn=cmd_selftest)
    sp = sub.add_parser("status"); sp.add_argument("--live", action="store_true"); sp.set_defaults(fn=cmd_status)
    sp = sub.add_parser("gen"); sp.add_argument("--n", type=int, required=True); sp.add_argument("--classes", default="A"); sp.add_argument("--out", default="data/wallets.json"); sp.add_argument("--password"); sp.add_argument("--force", action="store_true"); sp.set_defaults(fn=cmd_gen)
    sp = sub.add_parser("encrypt"); sp.add_argument("--wallets", "--in", dest="wallets", default="data/wallets.json"); sp.add_argument("--out", default="data/wallets.json"); sp.add_argument("--password"); sp.add_argument("--kdf", choices=["scrypt", "pbkdf2"], default="scrypt"); sp.set_defaults(fn=cmd_encrypt)
    sp = sub.add_parser("plan"); sp.add_argument("--preset", choices=["micro", "standard"]); sp.add_argument("--target", type=float); sp.add_argument("--budget", type=float); sp.add_argument("--depth", type=float); sp.add_argument("--wallets", type=int); sp.add_argument("--seed", type=int); sp.add_argument("--minshare", type=float); sp.add_argument("--maxshare", type=float); sp.add_argument("--out"); sp.set_defaults(fn=cmd_plan)
    sp = sub.add_parser("verify"); sp.add_argument("planfile"); sp.set_defaults(fn=cmd_verify)
    sp = sub.add_parser("doctor"); sp.add_argument("--plan", default="data/plan_micro.json"); sp.add_argument("--token"); sp.add_argument("--curve"); sp.add_argument("--wallets", default="data/wallets.json"); sp.add_argument("--password"); sp.add_argument("--gas", type=int, default=200000); sp.set_defaults(fn=cmd_doctor)
    sp = sub.add_parser("sync"); sp.set_defaults(fn=cmd_sync)

    sp = sub.add_parser("resume")
    sp.add_argument("--run", required=True)
    sp.add_argument("--send", action="store_true")
    sp.add_argument("--wallets", default="data/wallets.json")
    sp.add_argument("--password")
    sp.add_argument("--gas", type=int, default=200000)
    sp.add_argument("--slip-bps", dest="slip_bps", type=int, default=300)
    sp.add_argument("--timeout", type=float, default=60)
    sp.add_argument("--force", action="store_true")
    sp.set_defaults(fn=cmd_resume)

    sp = sub.add_parser("wallet")
    wsub = sp.add_subparsers(dest="action", required=True)
    wp = wsub.add_parser("encrypt")
    wp.add_argument("--in", dest="in_file", default="data/wallets.json")
    wp.add_argument("--out", default="data/wallets.json")
    wp.add_argument("--password")
    wp.add_argument("--kdf", choices=["scrypt", "pbkdf2"], default="scrypt")
    wp = wsub.add_parser("decrypt")
    wp.add_argument("--in", dest="in_file", default="data/wallets.json")
    wp.add_argument("--out", default="data/wallets.json")
    wp.add_argument("--password")
    sp.set_defaults(fn=cmd_wallet)

    sp = sub.add_parser("run")
    sp.add_argument("--plan", required=True)
    sp.add_argument("--token", required=True)
    sp.add_argument("--curve")
    sp.add_argument("--wallets", default="data/wallets.json")
    sp.add_argument("--password")
    sp.add_argument("--gas", type=int, default=200000)
    sp.add_argument("--slip-bps", dest="slip_bps", type=int, default=300)
    sp.add_argument("--timeout", type=float, default=60)
    sp.add_argument("--send", action="store_true")
    sp.add_argument("--sign", action="store_true")
    sp.add_argument("--force", action="store_true")
    sp.add_argument("--allow-zero-slippage", action="store_true")
    sp.add_argument("--dangerously-ignore-invariants", "--ignore-invariants", dest="dangerously_ignore_invariants", action="store_true")
    sp.add_argument("--allow-unverified-baseline", dest="allow_unverified_baseline", action="store_true")
    sp.add_argument("--allow-unverified-curve", dest="allow_unverified_curve", action="store_true")
    sp.set_defaults(fn=cmd_run)

    a = ap.parse_args()
    a.fn(a)

if __name__ == "__main__":
    main()
