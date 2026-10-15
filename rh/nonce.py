"""ROBINHIDDEN cross-process nonce reservation, coordination, and ownership.
Prevents concurrent execution processes from colliding on transaction nonces.
Uses OS file locks (fcntl.flock), process-level threading locks, and atomic persistent state tracking.
"""
import fcntl, json, os, secrets, threading

_thread_lock = threading.RLock()

def _ensure_dir(path: str, mode: int = 0o700):
    if not os.path.exists(path):
        os.makedirs(path, mode=mode, exist_ok=True)
    try:
        os.chmod(path, mode)
    except Exception:
        pass

def _load_state(state_path: str) -> dict:
    if not os.path.exists(state_path):
        return {}
    with open(state_path, "r") as f:
        content = f.read().strip()
        if not content:
            return {}
        try:
            return json.loads(content)
        except Exception as e:
            raise RuntimeError(f"Corrupted nonce state file at {state_path}: {e}")

def _claims_path(state_path: str) -> str:
    dir_name = os.path.dirname(os.path.abspath(state_path))
    base_name = os.path.basename(state_path)
    return os.path.join(dir_name, f".{base_name}.claims.json")

def _load_claims(claims_path: str) -> dict:
    if not os.path.exists(claims_path):
        return {}
    with open(claims_path, "r") as f:
        content = f.read().strip()
        if not content:
            return {}
        try:
            return json.loads(content)
        except Exception as e:
            raise RuntimeError(f"Corrupted nonce claims file at {claims_path}: {e}")

def _save_claims(claims: dict, claims_path: str) -> None:
    _ensure_dir(os.path.dirname(os.path.abspath(claims_path)), 0o700)
    tmp_path = f"{claims_path}.tmp.{secrets.token_hex(6)}.{os.getpid()}"
    fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(claims, f, indent=2)
            f.flush()
            os.fsync(fd)
        os.replace(tmp_path, claims_path)
    except Exception:
        if os.path.exists(tmp_path):
            try: os.remove(tmp_path)
            except Exception: pass
        raise

def claim_or_reserve_nonce(rpc, addr: str, prep_nonce: int = None, state_path: str = "data/.nonces.json", lock_dir: str = "data/.locks", owner_id: str = None):
    """Atomically claims a prepared nonce if valid and unclaimed (or owned by owner_id),
    or reserves the next available uncolliding nonce under OS-level wallet and global locks.
    Guarantees exclusive ownership across concurrent processes and threads, while allowing
    idempotent retry by the same execution/artifact owner.
    Returns (chosen_nonce, was_reused).
    """
    addr_norm = addr.lower()
    _ensure_dir(lock_dir, 0o700)
    lock_file = os.path.join(lock_dir, f"wallet_{addr_norm[2:] if addr_norm.startswith('0x') else addr_norm}.lock")
    lock_fd = os.open(lock_file, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        os.fchmod(lock_fd, 0o600)
    except Exception:
        pass

    with _thread_lock:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX)

            latest_count = None
            try:
                res_l = rpc.call("eth_getTransactionCount", [addr, "latest"])
                if res_l is not None:
                    latest_count = int(res_l, 16) if isinstance(res_l, str) else int(res_l)
            except Exception:
                pass

            pending_count = None
            try:
                res_p = rpc.call("eth_getTransactionCount", [addr, "pending"])
                if res_p is not None:
                    pending_count = int(res_p, 16) if isinstance(res_p, str) else int(res_p)
            except Exception:
                pass

            counts = [c for c in (latest_count, pending_count) if c is not None]
            if not counts:
                raise RuntimeError(
                    f"Unable to determine on-chain transaction count for {addr}: "
                    "both 'latest' and 'pending' queries failed or returned null"
                )
            on_chain = max(counts)
            confirmed_block_count = latest_count

            global_lock = os.path.join(lock_dir, "nonces_state.lock")
            gl_fd = os.open(global_lock, os.O_CREAT | os.O_RDWR, 0o600)
            try:
                os.fchmod(gl_fd, 0o600)
            except Exception:
                pass

            try:
                fcntl.flock(gl_fd, fcntl.LOCK_EX)

                disk_state = _load_state(state_path)
                local_reserved = disk_state.get(addr_norm, 0)
                c_path = _claims_path(state_path)
                claims = _load_claims(c_path)
                raw_claims = claims.get(addr_norm, {})

                # Normalize active claims to {int(nonce): str(owner_id)}.
                # Only retire claims when confirmed by block-state ('latest') count.
                # A pending-count advance alone is NOT evidence of block inclusion!
                active_claims = {}
                if isinstance(raw_claims, dict):
                    for k, v in raw_claims.items():
                        try:
                            n = int(k)
                            if confirmed_block_count is None or n >= confirmed_block_count:
                                active_claims[n] = str(v) if v is not None else ""
                        except (ValueError, TypeError):
                            pass
                elif isinstance(raw_claims, list):
                    for n in raw_claims:
                        if isinstance(n, int) and (confirmed_block_count is None or n >= confirmed_block_count):
                            active_claims[n] = ""

                min_valid_nonce = confirmed_block_count if confirmed_block_count is not None else on_chain
                was_reused = False
                if prep_nonce is not None and isinstance(prep_nonce, int) and prep_nonce >= min_valid_nonce:
                    existing_owner = active_claims.get(prep_nonce)
                    if prep_nonce not in active_claims:
                        chosen_nonce = prep_nonce
                        was_reused = True
                    elif not existing_owner or (owner_id and existing_owner == owner_id):
                        chosen_nonce = prep_nonce
                        was_reused = True
                    else:
                        candidate = on_chain
                        while candidate in active_claims:
                            candidate += 1
                        chosen_nonce = candidate
                        was_reused = False
                else:
                    candidate = on_chain
                    while candidate in active_claims:
                        candidate += 1
                    chosen_nonce = candidate
                    was_reused = False

                active_claims[chosen_nonce] = str(owner_id) if owner_id is not None else ""
                claims[addr_norm] = {str(k): v for k, v in sorted(active_claims.items())}
                _save_claims(claims, c_path)

                disk_state[addr_norm] = max(active_claims.keys()) + 1
                _ensure_dir(os.path.dirname(os.path.abspath(state_path)), 0o700)
                tmp_path = f"{state_path}.tmp.{secrets.token_hex(6)}.{os.getpid()}"
                fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                try:
                    os.fchmod(fd, 0o600)
                    with os.fdopen(fd, "w") as f:
                        json.dump(disk_state, f, indent=2)
                        f.flush()
                        os.fsync(fd)
                    os.replace(tmp_path, state_path)
                except Exception:
                    if os.path.exists(tmp_path):
                        try: os.remove(tmp_path)
                        except Exception: pass
                    raise

                return chosen_nonce, was_reused

            finally:
                try:
                    fcntl.flock(gl_fd, fcntl.LOCK_UN)
                finally:
                    os.close(gl_fd)

        finally:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            finally:
                os.close(lock_fd)

def reserve_nonce(rpc, addr: str, state_path: str = "data/.nonces.json", lock_dir: str = "data/.locks", owner_id: str = None) -> int:
    """Acquires an exclusive OS-level lock for the wallet, queries the on-chain pending count,
    reconciles with locally reserved nonces and active claims, and reserves the next available
    nonce atomically.
    """
    chosen, _ = claim_or_reserve_nonce(rpc, addr, prep_nonce=None, state_path=state_path, lock_dir=lock_dir, owner_id=owner_id)
    return chosen

def release_nonce(addr: str, nonce: int, state_path: str = "data/.nonces.json", lock_dir: str = "data/.locks", owner_id: str = None) -> None:
    """Rolls back an unused nonce reservation or claim if preflight operations fail before signing."""
    addr_norm = addr.lower()
    _ensure_dir(lock_dir, 0o700)
    lock_file = os.path.join(lock_dir, f"wallet_{addr_norm[2:] if addr_norm.startswith('0x') else addr_norm}.lock")
    lock_fd = os.open(lock_file, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        os.fchmod(lock_fd, 0o600)
    except Exception:
        pass

    with _thread_lock:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            global_lock = os.path.join(lock_dir, "nonces_state.lock")
            gl_fd = os.open(global_lock, os.O_CREAT | os.O_RDWR, 0o600)
            try:
                os.fchmod(gl_fd, 0o600)
            except Exception:
                pass
            try:
                fcntl.flock(gl_fd, fcntl.LOCK_EX)
                c_path = _claims_path(state_path)
                claims = _load_claims(c_path)
                if addr_norm in claims:
                    raw_claims = claims[addr_norm]
                    if isinstance(raw_claims, dict):
                        s_nonce = str(nonce)
                        if s_nonce in raw_claims:
                            if owner_id is None or raw_claims[s_nonce] in (owner_id, ""):
                                del raw_claims[s_nonce]
                                _save_claims(claims, c_path)
                    elif isinstance(raw_claims, list):
                        if nonce in raw_claims:
                            raw_claims.remove(nonce)
                            _save_claims(claims, c_path)

                state = _load_state(state_path)
                remaining_claims = claims.get(addr_norm, {})
                remaining_keys = [int(k) for k in remaining_claims.keys()] if isinstance(remaining_claims, dict) else [int(k) for k in remaining_claims]
                if remaining_keys:
                    state[addr_norm] = max(remaining_keys) + 1
                else:
                    state[addr_norm] = nonce
                    tmp_path = f"{state_path}.tmp.{secrets.token_hex(6)}.{os.getpid()}"
                    fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                    try:
                        os.fchmod(fd, 0o600)
                        with os.fdopen(fd, "w") as f:
                            json.dump(state, f, indent=2)
                            f.flush()
                            os.fsync(fd)
                        os.replace(tmp_path, state_path)
                    except Exception:
                        if os.path.exists(tmp_path):
                            try: os.remove(tmp_path)
                            except Exception: pass
                        raise
            finally:
                try:
                    fcntl.flock(gl_fd, fcntl.LOCK_UN)
                finally:
                    os.close(gl_fd)
        finally:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            finally:
                os.close(lock_fd)

def reconcile_nonce(rpc, addr: str, state_path: str = "data/.nonces.json", lock_dir: str = "data/.locks") -> int:
    """Reconciles the locally tracked nonce state with the on-chain count."""
    addr_norm = addr.lower()
    _ensure_dir(lock_dir, 0o700)
    lock_file = os.path.join(lock_dir, f"wallet_{addr_norm[2:] if addr_norm.startswith('0x') else addr_norm}.lock")
    lock_fd = os.open(lock_file, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        os.fchmod(lock_fd, 0o600)
    except Exception:
        pass
    with _thread_lock:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            res = rpc.call("eth_getTransactionCount", [addr, "latest"])
            if res is None:
                raise RuntimeError(f"Unable to reconcile nonce for {addr}: 'latest' query returned null")
            on_chain = int(res, 16) if isinstance(res, str) else int(res)

            global_lock = os.path.join(lock_dir, "nonces_state.lock")
            gl_fd = os.open(global_lock, os.O_CREAT | os.O_RDWR, 0o600)
            try:
                os.fchmod(gl_fd, 0o600)
            except Exception:
                pass
            try:
                fcntl.flock(gl_fd, fcntl.LOCK_EX)
                c_path = _claims_path(state_path)
                claims = _load_claims(c_path)
                if addr_norm in claims:
                    raw_claims = claims[addr_norm]
                    if isinstance(raw_claims, dict):
                        claims[addr_norm] = {k: v for k, v in raw_claims.items() if int(k) >= on_chain}
                    elif isinstance(raw_claims, list):
                        claims[addr_norm] = [n for n in raw_claims if n >= on_chain]
                    _save_claims(claims, c_path)

                state = _load_state(state_path)
                if state.get(addr_norm, 0) < on_chain:
                    state[addr_norm] = on_chain
                    tmp_path = f"{state_path}.tmp.{secrets.token_hex(6)}.{os.getpid()}"
                    fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                    try:
                        os.fchmod(fd, 0o600)
                        with os.fdopen(fd, "w") as f:
                            json.dump(state, f, indent=2)
                            f.flush()
                            os.fsync(fd)
                        os.replace(tmp_path, state_path)
                    except Exception:
                        if os.path.exists(tmp_path):
                            try: os.remove(tmp_path)
                            except Exception: pass
                        raise
            finally:
                try:
                    fcntl.flock(gl_fd, fcntl.LOCK_UN)
                finally:
                    os.close(gl_fd)

            return on_chain
        finally:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            finally:
                os.close(lock_fd)

def set_nonce_min(addr: str, min_next_nonce: int, state_path: str = "data/.nonces.json", lock_dir: str = "data/.locks") -> None:
    """Ensures local reservation state for addr tracks at least min_next_nonce under global lock."""
    addr_norm = addr.lower()
    _ensure_dir(lock_dir, 0o700)
    lock_file = os.path.join(lock_dir, f"wallet_{addr_norm[2:] if addr_norm.startswith('0x') else addr_norm}.lock")
    lock_fd = os.open(lock_file, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        os.fchmod(lock_fd, 0o600)
    except Exception:
        pass
    with _thread_lock:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            global_lock = os.path.join(lock_dir, "nonces_state.lock")
            gl_fd = os.open(global_lock, os.O_CREAT | os.O_RDWR, 0o600)
            try:
                os.fchmod(gl_fd, 0o600)
            except Exception:
                pass
            try:
                fcntl.flock(gl_fd, fcntl.LOCK_EX)
                state = _load_state(state_path)
                if state.get(addr_norm, 0) < min_next_nonce:
                    state[addr_norm] = min_next_nonce
                    _ensure_dir(os.path.dirname(os.path.abspath(state_path)), 0o700)
                    tmp_path = f"{state_path}.tmp.{secrets.token_hex(6)}.{os.getpid()}"
                    fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                    try:
                        os.fchmod(fd, 0o600)
                        with os.fdopen(fd, "w") as f:
                            json.dump(state, f, indent=2)
                            f.flush()
                            os.fsync(fd)
                        os.replace(tmp_path, state_path)
                    except Exception:
                        if os.path.exists(tmp_path):
                            try: os.remove(tmp_path)
                            except Exception: pass
                        raise
            finally:
                try:
                    fcntl.flock(gl_fd, fcntl.LOCK_UN)
                finally:
                    os.close(gl_fd)
        finally:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            finally:
                os.close(lock_fd)
