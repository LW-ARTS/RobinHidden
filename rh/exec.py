"""ROBINHIDDEN exec -- construction, signing (type-2/EIP-1559), and broadcasting of curve.buy (RHC 4663)."""
import json, time, threading
from . import crypto as C

ETH = 10 ** 18

def rlp(v) -> bytes:
    """Standard RLP compatible with crypto.rlp."""
    if isinstance(v, str):
        v = bytes.fromhex(v[2:] if v.startswith("0x") else v)
    return C.rlp(v)

def addr_bytes(a: str) -> bytes:
    return bytes.fromhex(a[2:] if a.startswith("0x") else a)

def calldata_buy(quote_in: int, min_tokens_out: int, recipient: str) -> bytes:
    sel = bytes.fromhex("59a87bc1")  # buy(uint256,uint256,address) -- verificado @85271310
    return sel + C.enc_val("uint256", quote_in) + C.enc_val("uint256", min_tokens_out) + C.enc_val("address", recipient)

def calldata_sell(token_in: int, min_quote_out: int, recipient: str) -> bytes:
    sel = bytes.fromhex("d04c6983")  # sell(uint256,uint256,address) -- verificado @85271310
    return sel + C.enc_val("uint256", token_in) + C.enc_val("uint256", min_quote_out) + C.enc_val("address", recipient)

def _curve_hex_bytes(value, size=None):
    """Decode canonical RPC hex without accepting whitespace or partial words."""
    if isinstance(value, str):
        if (not value.startswith("0x") or len(value[2:]) % 2 or
                any(ch not in "0123456789abcdefABCDEF" for ch in value[2:])):
            raise RuntimeError("Invalid Factory V2 hex response")
        raw = bytes.fromhex(value[2:])
    elif isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
    else:
        raise RuntimeError("Invalid Factory V2 response type")
    if size is not None and len(raw) != size:
        raise RuntimeError("Unexpected Factory V2 ABI response length")
    return raw


def _curve_input_address(value):
    if not isinstance(value, str):
        raise RuntimeError("Invalid token or Factory V2 address")
    raw = _curve_hex_bytes(value, 20)
    if not any(raw):
        raise RuntimeError("Zero token or Factory V2 address")
    return "0x" + raw.hex()


def _curve_abi_address(word):
    if len(word) != 32 or any(word[:12]):
        raise RuntimeError("Noncanonical Factory V2 address word")
    return "0x" + word[12:].hex()


def _curve_record_address(response, token):
    # V2 only: V1 word 1 is a deployer and cannot establish a curve binding.
    raw = _curve_hex_bytes(response, 15 * 32)
    words = [raw[i:i + 32] for i in range(0, len(raw), 32)]
    addresses = [_curve_abi_address(w) for w in words[:5]]
    values = [int.from_bytes(w, "big") for w in words]
    if (values[6] >= 1 << 24 or values[8] >= 1 << 16 or
            values[10] >= 1 << 8 or values[9] not in (0, 1) or
            values[14] not in (0, 1)):
        raise RuntimeError("Invalid Factory V2 narrow integer or boolean")
    tick_spacing = int.from_bytes(words[7], "big", signed=True)
    if not -(1 << 23) <= tick_spacing < (1 << 23):
        raise RuntimeError("Invalid Factory V2 int24 sign extension")
    if addresses[0] != token or values[14] != 1 or addresses[1] == "0x" + "0" * 40:
        raise RuntimeError("Factory V2 record does not prove the token-to-curve binding")
    return addresses[1]


def _curve_block_number(value):
    if (not isinstance(value, str) or not value.startswith("0x") or
            not value[2:] or any(ch not in "0123456789abcdefABCDEF" for ch in value[2:])):
        raise RuntimeError("Invalid block number during Factory V2 discovery")
    return int(value, 16)


def _curve_event_address(log, factory, topic, token, frm, to):
    if not isinstance(log, dict) or log.get("removed") is not False:
        raise RuntimeError("Malformed or removed Factory V2 launch event")
    if _curve_input_address(log.get("address")) != factory:
        raise RuntimeError("Launch event is not from the configured Factory V2")
    topics = log.get("topics")
    if not isinstance(topics, list) or len(topics) != 4:
        raise RuntimeError("Unexpected Factory V2 launch event topics")
    decoded = [_curve_hex_bytes(t, 32) for t in topics]
    if "0x" + decoded[0].hex() != topic:
        raise RuntimeError("Unexpected Factory V2 launch event signature")
    addresses = [_curve_abi_address(w) for w in decoded[1:]]
    if addresses[0] != token or addresses[1] == "0x" + "0" * 40:
        raise RuntimeError("Launch event does not prove the token-to-curve binding")
    data = _curve_hex_bytes(log.get("data"), 3 * 32)
    _curve_abi_address(data[:32])  # pairToken; the zero address is a native pair.
    block = _curve_block_number(log.get("blockNumber"))
    if not frm <= block <= to or not any(_curve_hex_bytes(log.get("blockHash"), 32)):
        raise RuntimeError("Launch event has invalid block metadata")
    return addresses[1]


def find_curve(c, cfg, token: str = None) -> str:
    """Resolve a proven Pons V2 curve, rejecting unsupported or malformed records."""
    if token is None:
        token = cfg
        from . import model as M
        cfg = M.load_cfg("data/config.json")
    token_clean = _curve_input_address(token)
    pons = cfg.get("pons", {}) if isinstance(cfg, dict) else {}
    factory = _curve_input_address(pons.get("factory_v2") if isinstance(pons, dict) else None)
    cd = C.sel("getLaunchedToken(address)") + C.enc_val("address", token_clean)
    try:
        response = c.call("eth_call", [{"to": factory, "data": "0x" + cd.hex()}, "latest"])
    except Exception:
        # An unavailable getter may be corroborated by a complete launch event.
        # A returned malformed/contradictory record is never masked by fallback.
        pass
    else:
        return _curve_record_address(response, token_clean)

    topic = "0x" + C.keccak256(b"TokenLaunched(address,address,address,address,uint256,uint256)").hex()
    configured_topic = cfg.get("topic0_tokenlaunched")
    if configured_topic is not None and configured_topic != topic:
        raise RuntimeError("Configured topic does not match the Factory V2 launch ABI")
    try:
        head = c.call("eth_getBlockByNumber", ["latest", False])
    except Exception:
        try:
            last = c.block_number()
        except Exception:
            raise RuntimeError("Cannot verify block height for Factory V2 discovery") from None
        if type(last) is not int or last < 0:
            raise RuntimeError("Invalid fallback block height for Factory V2 discovery")
    else:
        if not isinstance(head, dict):
            raise RuntimeError("Invalid block response during Factory V2 discovery")
        last = _curve_block_number(head.get("number"))

    token_topic = "0x" + C.enc_val("address", token_clean).hex()
    to = last
    for _ in range(20):
        frm = max(0, to - 500_000 + 1)
        try:
            logs = c.call("eth_getLogs", [{"address": factory, "topics": [topic, token_topic],
                                          "fromBlock": hex(frm), "toBlock": hex(to)}])
        except Exception:
            raise RuntimeError("Cannot verify Factory V2 launch events") from None
        if not isinstance(logs, list):
            raise RuntimeError("Invalid Factory V2 launch event response")
        if logs:
            curves = {_curve_event_address(log, factory, topic, token_clean, frm, to) for log in logs}
            if len(curves) != 1:
                raise RuntimeError("Conflicting Factory V2 token-to-curve bindings")
            return curves.pop()
        if frm == 0:
            break
        to = frm - 1
    raise RuntimeError("No verified Factory V2 curve for token %s" % token_clean)

def base_fee(c) -> int:
    blk = c.call("eth_getBlockByNumber", ["latest", False])
    return int(blk["baseFeePerGas"], 16) if blk and "baseFeePerGas" in blk else 0

_PREV_CURVE_RESERVES = {}

def jit_check_curve_state(c, curve: str, sample_addr: str, max_slip_bps: int = 300, force: bool = False, expected_reserves: tuple = None):
    """Just-in-Time (JIT) pre-flight check right before transaction dispatch.
    Verifies curve pause state, current Snipe Tax, and curve reserve/price slippage fail-closed."""
    # 0. Pause state check (fail-closed: any query error halts dispatch unless forced)
    try:
        p_res = c.call("eth_call", [{"to": curve, "data": "0x" + C.sel("paused()").hex()}, "latest"])
    except Exception as e:
        if not force:
            raise RuntimeError("JIT Check: Failed to verify curve pause state: %r. Halting dispatch to protect funds." % e)
        p_res = None

    if not force:
        if not p_res or not isinstance(p_res, str) or not p_res.startswith("0x") or len(p_res) < 3:
            raise RuntimeError("JIT Check: Failed to verify curve pause state: null, empty, or invalid response (%r). Halting dispatch to protect funds." % p_res)
        try:
            p_val = int(p_res, 16)
        except Exception as e:
            raise RuntimeError("JIT Check: Failed to verify curve pause state: non-hex response (%r): %r. Halting dispatch." % (p_res, e))
        if p_val not in (0, 1):
            raise RuntimeError("JIT Check: Failed to verify curve pause state: response is outside boolean domain (%d). Halting dispatch to protect funds." % p_val)
        if p_val == 1:
            raise RuntimeError("JIT Check: Curve contract is paused. Halting dispatch to protect funds.")

    # 1. Snipe Tax check
    cst_call = "0x" + C.sel("currentSnipeTaxBps(address)").hex() + C.enc_val("address", sample_addr).hex()
    cst_res = c.call("eth_call", [{"to": curve, "data": cst_call}, "latest"])
    if not cst_res or not isinstance(cst_res, str) or not cst_res.startswith("0x") or len(cst_res) < 3:
        raise RuntimeError("JIT Check: Snipe Tax query returned null or invalid response (%r)" % cst_res)
    st_bps = int(cst_res, 16)
    if st_bps > 0 and not force:
        raise RuntimeError("JIT Check: Snipe Tax active on curve (%d bps). Halting dispatch to protect funds." % st_bps)

    # 2. Reserves check
    res = c.call("eth_call", [{"to": curve, "data": "0x" + C.sel("getReserves()").hex()}, "latest"])
    if not res or not isinstance(res, str) or not res.startswith("0x") or len(res) < 130:
        raise RuntimeError("JIT Check: Curve getReserves() returned null or invalid response (%r)" % res)
    qr = int(res[2:66], 16)
    tr = int(res[66:130], 16)
    if qr <= 0 or tr <= 0:
        raise RuntimeError("JIT Check: Zero or negative reserves detected: quote=%d token=%d" % (qr, tr))

    # 3. Slippage and price bounding
    curve_key = curve.lower()
    prev = expected_reserves or _PREV_CURVE_RESERVES.get(curve_key)
    if prev:
        prev_qr, prev_tr = prev
        if prev_qr > 0 and prev_tr > 0:
            num = abs(qr * prev_tr - prev_qr * tr) * 10000
            denom = prev_qr * tr
            if num > denom * max_slip_bps and not force:
                price_diff_bps = (num + denom - 1) // denom
                raise RuntimeError(
                    "JIT Check: Price deviation of %d bps exceeds max_slip_bps (%d bps). Halting dispatch." %
                    (price_diff_bps, max_slip_bps)
                )
    else:
        if not force:
            raise RuntimeError("JIT Check: No comparison baseline (expected_reserves or prior curve history) available to verify slippage. Halting dispatch to protect funds.")
    _PREV_CURVE_RESERVES[curve_key] = (qr, tr)

    return {"snipe_tax_bps": st_bps, "quote_reserve": qr, "token_reserve": tr}

def simulate_and_estimate_buy(c, from_addr: str, curve: str, value_wei: int, cd_data: bytes, gas_ceiling: int) -> int:
    """Simulates the buy transaction via eth_call and dynamically estimates gas limit."""
    call_payload = {
        "from": from_addr,
        "to": curve,
        "value": hex(value_wei),
        "data": "0x" + cd_data.hex() if isinstance(cd_data, (bytes, bytearray)) else cd_data
    }
    # Simulation
    try:
        c.call("eth_call", [call_payload, "latest"])
    except Exception as e:
        raise RuntimeError("Pre-flight eth_call simulation failed for wallet %s: %r. Aborting before signing." % (from_addr, e))

    # Dynamic gas estimation
    try:
        est_hex = c.call("eth_estimateGas", [call_payload])
        est_gas = int(est_hex, 16) if isinstance(est_hex, str) else int(est_hex)
    except Exception as e:
        raise RuntimeError("Dynamic eth_estimateGas failed for wallet %s: %r. Aborting before signing." % (from_addr, e))

    # 20% safety margin, minimum floor of 21000
    needed_gas = max(21000, int(est_gas * 1.2))
    if needed_gas > gas_ceiling:
        raise RuntimeError("Estimated gas (%d) exceeds configured ceiling (%d) for wallet %s. Aborting." % (needed_gas, gas_ceiling, from_addr))
    return needed_gas

def sign_tx(chain_id: int, to: str, value: int, data: bytes, nonce: int,
            gas: int, max_fee: int, prio: int, priv: int):
    """Sign canonical type-2 (EIP-1559) and return (txhash_hex, raw_hex, (r,s,v), msg_hash)."""
    to_bytes, data_bytes = C.validate_type2_inputs(chain_id, priv, nonce, to, value, data, max_fee, prio, gas)
    unsigned = [chain_id, nonce, prio, max_fee, gas, to_bytes, value, data_bytes, []]
    h = C.keccak256(b"\x02" + C.rlp(unsigned))
    r, s, recid = C.sign(h, priv)
    if type(recid) is not int or recid not in (0, 1):
        raise ValueError("Signature recovery identifier cannot be represented as type-2 yParity")
    v = recid
    raw = b"\x02" + C.rlp(unsigned + [v, r, s])
    return "0x" + C.keccak256(raw).hex(), "0x" + raw.hex(), (r, s, v), h

def recover_signer(raw_hex: str, chain_id: int) -> str:
    """Decode the canonical raw type-2 (EIP-1559) transaction again and return the signer address."""
    raw = bytes.fromhex(raw_hex[2:] if isinstance(raw_hex, str) and raw_hex.startswith("0x") else raw_hex)
    if raw[0] != 0x02:
        raise ValueError("not type-2 (expected 0x02 prefix)")
    items = C.rlp_decode(raw[1:])
    if not isinstance(items, list) or len(items) != 12:
        raise ValueError("incorrect number of type-2 fields: expected 12, received %d" % len(items))
    if C.rlp(items) != raw[1:]:
        raise ValueError("Noncanonical type-2 RLP encoding")
    for index, bits in ((0, 256), (1, 64), (2, 256), (3, 256), (4, 64),
                        (6, 256), (9, 8), (10, 256), (11, 256)):
        field = items[index]
        if (not isinstance(field, bytes) or len(field) > bits // 8 or
                (field and field[0] == 0)):
            raise ValueError("Noncanonical type-2 integer field")
    if (not isinstance(items[5], bytes) or len(items[5]) not in (0, 20) or
            not isinstance(items[7], bytes) or not isinstance(items[8], list)):
        raise ValueError("Invalid type-2 address, calldata or access list")
    for entry in items[8]:
        if (not isinstance(entry, list) or len(entry) != 2 or
                not isinstance(entry[0], bytes) or len(entry[0]) != 20 or
                not isinstance(entry[1], list) or
                any(not isinstance(key, bytes) or len(key) != 32 for key in entry[1])):
            raise ValueError("Invalid type-2 access-list entry")
    def _as_int(x):
        return int.from_bytes(x, "big") if isinstance(x, (bytes, bytearray)) else x
    cid = _as_int(items[0])
    if cid == 0 or _as_int(items[4]) < 21000 or _as_int(items[2]) > _as_int(items[3]):
        raise ValueError("Invalid type-2 chain, gas or fee fields")
    if cid != chain_id:
        raise ValueError("chainId mismatch: %d != %d" % (cid, chain_id))
    unsigned = items[:9]
    h = C.keccak256(b"\x02" + C.rlp(unsigned))
    v = _as_int(items[9])
    r = _as_int(items[10])
    s = _as_int(items[11])
    if v not in (0, 1) or not 1 <= r < C.N or not 1 <= s <= C.N // 2:
        raise ValueError("Noncanonical type-2 signature parity or high-S value")
    return C.pub_to_address(C.recover(h, r, s, v))

def send_batch(c, rows, timeout_s=60.0, max_concurrency=10, on_event=None):
    """Broadcast according to staggered slots, with limited concurrency and incremental event recording."""
    res = {r["txhash"]: None for r in rows}
    done = threading.Event()
    sem = threading.Semaphore(max_concurrency)

    def worker(r, delay):
        elapsed = 0.0
        while elapsed < delay:
            if done.is_set():
                res[r["txhash"]] = {"sent": False, "err": "canceled before broadcast"}
                return
            step = min(0.2, delay - elapsed)
            time.sleep(step)
            elapsed += step

        if done.is_set():
            res[r["txhash"]] = {"sent": False, "err": "canceled before broadcast"}
            return

        with sem:
            if done.is_set():
                res[r["txhash"]] = {"sent": False, "err": "canceled before broadcast"}
                return

            # 1. Broadcast to the network
            try:
                c.call("eth_sendRawTransaction", [r["raw"]])
            except Exception as e:
                err_msg = repr(e)[:160]
                res[r["txhash"]] = {"sent": False, "err": err_msg}
                if on_event:
                    try:
                        on_event("broadcast_error", r["txhash"], {"err": err_msg})
                    except Exception:
                        pass
                return

            # After RPC acknowledgment, sent remains True
            res[r["txhash"]] = {"sent": True, "status": None}

            # 2. Local journal recording (persistence failures do not change sent)
            if on_event:
                try:
                    on_event("broadcast", r["txhash"], {"slot": r.get("slot"), "addr": r["addr"]})
                except Exception as jerr:
                    res[r["txhash"]]["persistence_warn"] = repr(jerr)[:160]

            t0 = time.time()
            stagger = 0.4 + 0.05 * (r.get("slot", 0) % 5)
            while time.time() - t0 < timeout_s and not done.is_set():
                try:
                    rcpt = c.call("eth_getTransactionReceipt", [r["txhash"]])
                    if rcpt is not None:
                        res[r["txhash"]].update({
                            "sent": True,
                            "status": rcpt.get("status"),
                            "block": int(rcpt.get("blockNumber", "0x0"), 16),
                            "gasUsed": int(rcpt.get("gasUsed", "0x0"), 16)
                        })
                        info = res[r["txhash"]]
                        if on_event:
                            try:
                                on_event("receipt", r["txhash"], info)
                            except Exception as jerr:
                                res[r["txhash"]]["persistence_warn"] = repr(jerr)[:160]
                        return
                except Exception:
                    pass
                time.sleep(stagger)
            res[r["txhash"]]["status"] = None
            if on_event:
                try:
                    on_event("timeout", r["txhash"], {"elapsed": time.time() - t0})
                except Exception:
                    pass

    tmin = min((r.get("delay_s", 0.0) for r in rows), default=0.0)
    ths = [threading.Thread(target=worker, args=(r, max(0.0, r.get("delay_s", 0.0) - tmin))) for r in rows]
    for t in ths:
        t.start()

    max_delay = max((r.get("delay_s", 0.0) - tmin for r in rows), default=0.0)
    deadline = time.time() + max_delay + timeout_s + 5.0

    try:
        while any(t.is_alive() for t in ths) and time.time() < deadline:
            time.sleep(0.25)
    except KeyboardInterrupt:
        print("\nInterrupcao pelo operador! Parando workers...")
        done.set()

    done.set()
    for t in ths:
        t.join(timeout=1.0)
    return res
