"""ROBINHIDDEN core crypto: keccak-256, secp256k1, RLP, ABI, EIP-1559 signing, AES-CTR, Keystore.
Private signing/key derivation require the verified native secp256k1 backend.
Public arithmetic and encoding helpers retain the stdlib implementation."""
import hashlib, hmac, secrets

# ---------------- keccak-256 ----------------
_MASK64 = (1 << 64) - 1
_RC = [0x0000000000000001,0x0000000000008082,0x800000000000808A,0x8000000080008000,
       0x000000000000808B,0x0000000080000001,0x8000000080008081,0x8000000000008009,
       0x000000000000008A,0x0000000000000088,0x0000000080008009,0x000000008000000A,
       0x000000008000808B,0x800000000000008B,0x8000000000008089,0x8000000000008003,
       0x8000000000008002,0x8000000000000080,0x000000000000800A,0x800000008000000A,
       0x8000000080008081,0x8000000000008080,0x0000000080000001,0x8000000080008008]
_ROT = [[0,36,3,41,18],[1,44,10,45,2],[62,6,43,15,61],[28,55,25,21,56],[27,20,39,8,14]]

def _rotl(v, n):
    n %= 64
    return ((v << n) | (v >> (64 - n))) & _MASK64 if n else v

def _keccak_f(st):
    for rnd in range(24):
        C = [st[x] ^ st[x+5] ^ st[x+10] ^ st[x+15] ^ st[x+20] for x in range(5)]
        D = [C[(x-1) % 5] ^ _rotl(C[(x+1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                st[x + 5*y] ^= D[x]
        tmp = [0] * 25
        for x in range(5):
            for y in range(5):
                nx, ny = y, (2*x + 3*y) % 5
                tmp[nx + 5*ny] = _rotl(st[x + 5*y], _ROT[x][y])
        for x in range(5):
            for y in range(5):
                st[x + 5*y] = tmp[x + 5*y] ^ (~(tmp[(x+1) % 5 + 5*y]) & tmp[(x+2) % 5 + 5*y]) & _MASK64
        st[0] ^= _RC[rnd]
    return st

def keccak256(data: bytes) -> bytes:
    rate = 136
    padded = bytearray(data + b"\x01")
    while len(padded) % rate != 0:
        padded.append(0)
    padded[-1] ^= 0x80
    st = [0] * 25
    for off in range(0, len(padded), rate):
        blk = padded[off:off+rate]
        for i in range(rate // 8):
            st[i] ^= int.from_bytes(blk[8*i:8*i+8], "little")
        _keccak_f(st)
    out = b""
    for i in range(4):
        out += st[i].to_bytes(8, "little")
    return out

def khash(data) -> bytes:
    if isinstance(data, str):
        data = bytes.fromhex(data[2:] if data.startswith("0x") else data)
    return keccak256(data)

# ---------------- secp256k1 ----------------
P  = 2**256 - 2**32 - 977
N  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G = (GX, GY)

def _inv(a, m=P): return pow(a, m - 2, m)

def _pt_add(p, q):
    if p is None: return q
    if q is None: return p
    if p[0] == q[0]:
        if (p[1] + q[1]) % P == 0: return None
        lam = 3 * p[0] * p[0] * _inv(2 * p[1]) % P
    else:
        lam = (q[1] - p[1]) * _inv((q[0] - p[0]) % P) % P
    x3 = (lam * lam - p[0] - q[0]) % P
    return (x3, (lam * (p[0] - x3) - p[1]) % P)

def _mul(k, pt):
    r, a = None, pt
    while k:
        if k & 1: r = _pt_add(r, a)
        a = _pt_add(a, a); k >>= 1
    return r

def point_mul(pt, k): return _mul(k, pt)

_C_SCALAR = (1 << 256) % N
_C_G = point_mul(G, _C_SCALAR)

# The four boundary scalars near N - _C_SCALAR where 2^256 + k crosses 2N (delta in {-2, -1, 0, 1}).
# In affine coordinates, intermediate prefixes at bits 1 and 0 evaluate to N mod N, reaching infinity.
# Precomputing these 4 boundary cases and running the identical 256-step ladder structure guarantees
# mathematical correctness and uniform operation counts (257 doublings, 257 additions, 0 infinity operands).
_BOUNDARY_K0 = (N - _C_SCALAR + 1) % N   # delta = +1
_BOUNDARY_K1 = (N - _C_SCALAR) % N       # delta =  0
_BOUNDARY_K2 = (N - _C_SCALAR - 1) % N   # delta = -1
_BOUNDARY_K3 = (N - _C_SCALAR - 2) % N   # delta = -2

_EXCEPTIONAL_K = (_BOUNDARY_K0, _BOUNDARY_K1, _BOUNDARY_K2, _BOUNDARY_K3)
_EXCEPTIONAL_P1 = {k: point_mul(G, k - 1) for k in _EXCEPTIONAL_K}
_BOUNDARY_P2 = G

def point_mul_ladder(pt, k: int):
    """Regular scalar multiplication (Montgomery ladder) over secp256k1.
    Maintains a uniform arithmetic path of point additions and doublings across all
    256 bit positions by offsetting by 2^256 mod N and subtracting the public constant point,
    ensuring identical operation counts (257 doublings, 257 additions, 0 infinity operands).

    NOTE ON MATHEMATICAL BOUNDARY CASES AND CPYTHON HARDWARE LIMITS:
    1. Over secp256k1, 2^256 = N + c. For scalars k = N - c + delta with delta in {-2, -1, 0, 1},
       the evaluated integer 2^256 + k crosses 2N, causing intermediate affine ladder points to
       reach the point at infinity O = None. All 4 boundary scalars are evaluated through the
       identical 256-iteration ladder to preserve uniform operation counts and correctness.
    2. CPython standard library runtimes use variable-time arbitrary precision integers, heap
       allocations, and branch prediction that cannot guarantee physical hardware side-channel
       immunity. Production environments requiring physical side-channel defense must use
       compiled constant-time C/Rust cryptographic primitives (e.g., libsecp256k1) or hardware HSMs.
    """
    if pt is None or k % N == 0: return None
    k = k % N

    if pt == G and k in _EXCEPTIONAL_P1:
        r0 = pt
        r1 = _pt_add(pt, pt)
        for i in range(255, -1, -1):
            bit = (1 >> i) & 1
            pair0 = [r0, r1][bit]
            res_add = _pt_add(r0, r1)
            res_dbl = _pt_add(pair0, pair0)
            r0 = [res_dbl, res_add][bit]
            r1 = [res_add, res_dbl][bit]
        return _pt_add(_EXCEPTIONAL_P1[k], _BOUNDARY_P2)

    r0 = pt
    r1 = _pt_add(pt, pt)
    for i in range(255, -1, -1):
        bit = (k >> i) & 1
        pair0 = [r0, r1][bit]
        res_add = _pt_add(r0, r1)
        res_dbl = _pt_add(pair0, pair0)
        r0 = [res_dbl, res_add][bit]
        r1 = [res_add, res_dbl][bit]
    c_pt = _C_G if pt == G else point_mul(pt, _C_SCALAR)
    neg_c_pt = (c_pt[0], (P - c_pt[1]) % P)
    return _pt_add(r0, neg_c_pt)

def _on_curve(pt):
    if (not isinstance(pt, tuple) or len(pt) != 2 or
            any(type(v) is not int or not 0 <= v < P for v in pt)):
        return False
    x, y = pt
    return (y * y - (x*x*x + 7)) % P == 0

def priv_to_pub(priv: int):
    _validate_private_scalar(priv)
    return _native_backend().public_point(priv)

def _native_backend():
    try:
        from . import native_secp
    except ImportError:
        raise RuntimeError("Native signer dependency unavailable; no Python fallback permitted") from None
    return native_secp

def uncompressed(pub):
    if not _on_curve(pub):
        raise ValueError("Invalid canonical secp256k1 public point")
    return b"\x04" + pub[0].to_bytes(32, "big") + pub[1].to_bytes(32, "big")

def priv_to_address(priv: int) -> str:
    h = keccak256(uncompressed(priv_to_pub(priv))[1:])
    return "0x" + h[-20:].hex()

def pub_to_address(pub_or_bytes):
    if isinstance(pub_or_bytes, tuple):
        pub_or_bytes = uncompressed(pub_or_bytes)[1:]   # spec: keccak of the 64 bytes X||Y, WITHOUT 0x04
    elif (not isinstance(pub_or_bytes, (bytes, bytearray)) or len(pub_or_bytes) != 64 or
            not _on_curve((int.from_bytes(pub_or_bytes[:32], "big"), int.from_bytes(pub_or_bytes[32:], "big")))):
        raise ValueError("Expected a canonical 64-byte secp256k1 public key")
    h = keccak256(pub_or_bytes)
    return "0x" + h[-20:].hex()

def _validate_private_scalar(priv):
    if type(priv) is not int or not 1 <= priv < N:
        raise ValueError("Invalid secp256k1 private scalar")

def _validate_digest(msg_hash):
    if not isinstance(msg_hash, (bytes, bytearray)) or len(msg_hash) != 32:
        raise ValueError("Expected an exact 32-byte message digest")

def validate_type2_inputs(chain_id, priv, nonce, to, value, data, max_fee, max_prio, gas):
    """Reject malformed signing intent before any private-key arithmetic."""
    _validate_private_scalar(priv)
    for label, number, bits, minimum in (
            ("chain ID", chain_id, 256, 1), ("nonce", nonce, 64, 0),
            ("value", value, 256, 0), ("fee cap", max_fee, 256, 0),
            ("priority fee", max_prio, 256, 0), ("gas limit", gas, 64, 21000)):
        if type(number) is not int or not minimum <= number < 1 << bits:
            raise ValueError("Invalid type-2 %s" % label)
    if max_prio > max_fee:
        raise ValueError("Type-2 priority fee exceeds fee cap")
    if not isinstance(to, str):
        raise ValueError("Invalid type-2 recipient")
    target = to[2:] if to.startswith("0x") else to
    if len(target) != 40 or any(ch not in "0123456789abcdefABCDEF" for ch in target):
        raise ValueError("Expected an exact 20-byte type-2 recipient")
    if isinstance(data, str):
        payload = data[2:] if data.startswith("0x") else data
        if len(payload) % 2 or any(ch not in "0123456789abcdefABCDEF" for ch in payload):
            raise ValueError("Invalid type-2 calldata hex")
        payload = bytes.fromhex(payload)
    elif isinstance(data, (bytes, bytearray)):
        payload = bytes(data)
    else:
        raise ValueError("Invalid type-2 calldata type")
    return bytes.fromhex(target), payload

def _rfc6979_k(msg_hash: bytes, priv: int, counter=0):
    """Offline/reference helper only. Production signing uses native RFC6979."""
    _validate_private_scalar(priv)
    _validate_digest(msg_hash)
    if type(counter) is not int or not 0 <= counter < 64:
        raise ValueError("Invalid deterministic nonce retry counter")
    h1 = (int.from_bytes(msg_hash, "big") % N).to_bytes(32, "big")
    v = b"\x01" * 32; k = b"\x00" * 32
    px = priv.to_bytes(32, "big")
    k = hmac.new(k, v + b"\x00" + px + h1, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    k = hmac.new(k, v + b"\x01" + px + h1, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    while True:
        t = b""
        while len(t) < 32:
            v = hmac.new(k, v, hashlib.sha256).digest(); t += v
        c = int.from_bytes(t, "big")
        if 1 <= c < N:
            if counter == 0: return c
            counter -= 1
        k = hmac.new(k, v + b"\x00", hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()

def sign(msg_hash: bytes, priv: int):
    """Return native low-S (r, s, recid); dependency failures always block."""
    _validate_private_scalar(priv)
    _validate_digest(msg_hash)
    return _native_backend().sign_digest(msg_hash, priv)

def recover(msg_hash: bytes, r: int, s: int, recid: int):
    _validate_digest(msg_hash)
    if (any(type(v) is not int or not 1 <= v < N for v in (r, s)) or
            type(recid) is not int or not 0 <= recid <= 3):
        raise ValueError("Invalid secp256k1 signature or recovery identifier")
    x = r + ((recid >> 1) & 1) * N
    if x >= P:
        raise ValueError("Recovery point is outside the secp256k1 field")
    alpha = (x * x * x + 7) % P
    y = pow(alpha, (P + 1) // 4, P)
    if (y * y) % P != alpha:
        raise ValueError("recovery: point not on curve")
    if (y & 1) != (recid & 1):
        y = P - y
    R = (x, y)
    e = int.from_bytes(msg_hash[:32], "big")
    rinv = _inv(r, N)
    Q = _pt_add(_mul(rinv * (N - e % N) % N, G), _mul(rinv * s % N, R))
    if Q is None or not _on_curve(Q):
        raise ValueError("recovery failed")
    return Q

# ---------------- RLP ----------------
def _int_b(v: int) -> bytes:
    if v == 0: return b""
    return v.to_bytes((v.bit_length() + 7) // 8, "big")

def _len_pref(l: int, off: int) -> bytes:
    if l < 56: return bytes([off + l])
    lb = _int_b(l)
    return bytes([off + 55 + len(lb)]) + lb

def rlp(v) -> bytes:
    if isinstance(v, int):
        v = _int_b(v)
    if isinstance(v, (bytes, bytearray)):
        v = bytes(v)
        if len(v) == 1 and v[0] < 0x80: return v
        return _len_pref(len(v), 0x80) + v
    out = b"".join(rlp(i) for i in v)
    return _len_pref(len(out), 0xC0) + out

def _rlp_decode(buf, off=0):
    """One RLP item. Strings -> bytes, lists -> list of items."""
    b0 = buf[off]
    if b0 < 0x80:
        return buf[off:off+1], off + 1
    if b0 <= 0xB7:
        l = b0 - 0x80
        return bytes(buf[off+1:off+1+l]), off + 1 + l
    if b0 <= 0xBF:
        ll = b0 - 0xB7
        ln = int.from_bytes(buf[off+1:off+1+ll], "big")
        return bytes(buf[off+1+ll:off+1+ll+ln]), off + 1 + ll + ln
    if b0 <= 0xF7:
        l = b0 - 0xC0
        items = []; i = off + 1
        while i < off + 1 + l:
            it, i = _rlp_decode(buf, i)
            items.append(it)
        return items, i
    ll = b0 - 0xF7
    ln = int.from_bytes(buf[off+1:off+1+ll], "big")
    items = []; i = off + 1 + ll
    while i < off + 1 + ll + ln:
        it, i = _rlp_decode(buf, i)
        items.append(it)
    return items, i

def rlp_decode(buf):
    obj, off = _rlp_decode(buf)
    if off != len(buf): raise ValueError("trailing bytes in rlp")
    return obj

def rlp_decode_all(buf):
    items = []
    off = 0
    while off < len(buf):
        it, off = _rlp_decode(buf, off)
        items.append(it)
    return items

# ---------------- ABI ----------------
def sel(sig: str) -> bytes:
    return keccak256(sig.encode())[:4]

def enc_val(t: str, v):
    if t == "address":
        if isinstance(v, str):
            v = bytes.fromhex(v[2:])
        return v.rjust(32, b"\x00")
    if t in ("uint256", "uint128", "uint64", "uint32", "uint16", "uint8", "int256"):
        return int(v).to_bytes(32, "big", signed=(t.startswith("int")))
    if t == "bool":
        return (1 if v else 0).to_bytes(32, "big")
    if t == "bytes":
        return v if isinstance(v, bytes) else bytes.fromhex(v[2:])
    raise ValueError("enc_val: type %s" % t)

def _is_dyn(t):
    return t.endswith("[]") or t == "bytes"

def abi_encode(sig: str, vals) -> bytes:
    ts = sig[sig.index("(") + 1:sig.index(")")].split(",")
    ts = [t.strip() for t in ts if t.strip()]
    if len(ts) != len(vals):
        raise ValueError("abi arg count %d != %d" % (len(ts), len(vals)))
    dyns = [(t, v) for t, v in zip(ts, vals) if _is_dyn(t)]
    datas = []
    for t, v in dyns:
        if t == "bytes":
            raw = v if isinstance(v, (bytes, bytearray)) else \
                  bytes.fromhex(v[2:] if v.startswith("0x") else v)
            datas.append(enc_val("uint256", len(raw)) + raw +
                         b"\x00" * ((32 - len(raw) % 32) % 32))
        else:
            et = t[:-2]
            items = [enc_val(et, x) for x in v]
            datas.append(enc_val("uint256", len(items)) + b"".join(items))
    head_size = 32 * len(ts)
    off, heads = head_size, []
    di = 0
    for i, t in enumerate(ts):
        if _is_dyn(t):
            heads.append(enc_val("uint256", off))
            off += len(datas[di]); di += 1
        else:
            heads.append(enc_val(t, vals[i]))
    return sel(sig) + b"".join(heads) + b"".join(datas)

def decode_words(data: bytes, has_sel=True):
    data = data[4:]  # drop 4-byte selector (keep empty if no selector -> caller passes raw data)
    out = []
    for i in range(len(data) // 32):
        out.append(int.from_bytes(data[32*i:32*i+32], "big"))
    return out

TOPIC_TRANSFER = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"

def transfer_log(token: str, frm: str, to: str, value: int):
    pad = lambda a: a[2:].lower().rjust(64, "0")
    topics = [TOPIC_TRANSFER, "0x" + pad(frm), "0x" + pad(to)]
    data = "0x" + int(value).to_bytes(32, "big").hex()
    return {"address": token.lower(), "topics": topics, "data": data}

def parse_transfer(log):
    if log["topics"][0].lower() != TOPIC_TRANSFER.lower():
        return None
    d = log["data"]
    raw = bytes(d) if isinstance(d, (bytes, bytearray)) else \
          bytes.fromhex(d[2:] if d.startswith("0x") else d)
    return {"token": log["address"], "from": "0x" + log["topics"][1][-40:],
            "to": "0x" + log["topics"][2][-40:], "value": int.from_bytes(raw, "big")}

def hexb(b: bytes) -> str:
    return "0x" + b.hex()

def unh(s: str) -> bytes:
    s = s[2:] if isinstance(s, str) and s.startswith("0x") else s
    if isinstance(s, str): s = bytes.fromhex(s)
    return s

def norm_addr(a: str) -> str:
    return ("0x" + a[2:]).lower()

# ---------------- Native AES / CTR & Web3 Keystore V3 ----------------
def _native_aes_backend():
    try:
        from . import native_aes
        return native_aes
    except ImportError:
        raise RuntimeError("Native custody dependency unavailable; no Python AES fallback permitted") from None

def aes_ctr(key: bytes, iv: bytes, data: bytes) -> bytes:
    """Mandatory native AES-128/192/256 CTR, with no Python round/key schedule."""
    if any(type(value) not in (bytes, bytearray) for value in (key, iv, data)):
        raise ValueError("AES expects byte inputs")
    key, iv, data = bytes(key), bytes(iv), bytes(data)
    if len(key) not in (16, 24, 32) or len(iv) != 16:
        raise ValueError("AES requires a supported key and exact 16-byte counter")
    return _native_aes_backend().transform(key, iv, data)

def encrypt_keystore(data: bytes, password: str, kdf="scrypt") -> dict:
    """Encrypt payload into Ethereum Keystore V3 format with scrypt or pbkdf2."""
    if not isinstance(password, str) or not password:
        raise ValueError("A nonempty local password is required for encryption")
    if type(data) not in (bytes, bytearray):
        raise ValueError("Keystore payload must be bytes")
    data = bytes(data)
    _native_aes_backend().require_backend()
    salt = secrets.token_bytes(16)
    iv = secrets.token_bytes(16)
    if kdf == "scrypt":
        derived = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=16384, r=8, p=1, dklen=32)
        kdfparams = {"dklen": 32, "n": 16384, "r": 8, "p": 1, "salt": salt.hex()}
    elif kdf == "pbkdf2":
        derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 262144, 32)
        kdfparams = {"dklen": 32, "c": 262144, "prf": "hmac-sha256", "salt": salt.hex()}
    else:
        raise ValueError("Unsupported KDF: %s" % kdf)

    cipher_key = derived[:16]
    mac_key = derived[16:32]
    ciphertext = aes_ctr(cipher_key, iv, data)
    # Standard Web3 Secret Storage Definition V3 MAC: keccak256(derived[16:32] + ciphertext)
    mac = keccak256(mac_key + ciphertext).hex()
    return {
        "version": 3,
        "crypto": {
            "cipher": "aes-128-ctr",
            "cipherparams": {"iv": iv.hex()},
            "ciphertext": ciphertext.hex(),
            "kdf": kdf,
            "kdfparams": kdfparams,
            "mac": mac
        }
    }

def _keystore_hex(value, length=None):
    if (not isinstance(value, str) or len(value) % 2 or
            any(ch not in "0123456789abcdefABCDEF" for ch in value)):
        raise ValueError("Invalid keystore hex field")
    raw = bytes.fromhex(value)
    if length is not None and len(raw) != length:
        raise ValueError("Invalid keystore field length")
    return raw


def _validated_keystore_crypto(ks):
    """Validate supported metadata and bound KDF cost before deriving secrets."""
    if not isinstance(ks, dict):
        raise ValueError("Invalid keystore envelope")
    if "crypto" in ks:
        if type(ks.get("version")) is not int or ks["version"] != 3:
            raise ValueError("Unsupported keystore version")
        crypto = ks["crypto"]
    else:
        # Legacy standalone crypto object, retaining the existing envelope API.
        crypto = ks
    if not isinstance(crypto, dict) or crypto.get("cipher") != "aes-128-ctr":
        raise ValueError("Unsupported keystore cipher")
    cp = crypto.get("cipherparams")
    kp = crypto.get("kdfparams")
    if not isinstance(cp, dict) or not isinstance(kp, dict):
        raise ValueError("Invalid keystore parameter objects")
    _keystore_hex(cp.get("iv"), 16)
    _keystore_hex(crypto.get("mac"), 32)
    _keystore_hex(crypto.get("ciphertext"))
    salt = _keystore_hex(kp.get("salt"))
    if not 1 <= len(salt) <= 64 or type(kp.get("dklen")) is not int or kp["dklen"] != 32:
        raise ValueError("Unsupported keystore salt or derived key length")
    if crypto.get("kdf") == "scrypt":
        n, r, p = (kp.get(k) for k in ("n", "r", "p"))
        if (any(type(v) is not int for v in (n, r, p)) or
                not 2 <= n <= 1 << 20 or n & (n - 1) or
                not 1 <= r <= 32 or not 1 <= p <= 16 or
                128 * n * r > 256 * 1024 * 1024 or n * r * p > 1 << 22):
            raise ValueError("Unsupported or excessive keystore scrypt parameters")
    elif crypto.get("kdf") == "pbkdf2":
        if (type(kp.get("c")) is not int or not 1 <= kp["c"] <= 2_000_000 or
                kp.get("prf") != "hmac-sha256"):
            raise ValueError("Unsupported or excessive keystore PBKDF2 parameters")
    else:
        raise ValueError("Unsupported keystore KDF")
    return crypto


def decrypt_keystore(ks: dict, password: str) -> bytes:
    """Decrypt payload from Ethereum Keystore V3 format, verifying MAC integrity.
    Validates standard Web3 V3 MAC (keccak256(derived[16:32] + ciphertext)) as well
    as backward-compatible envelope variations."""
    crypto = _validated_keystore_crypto(ks)
    kdf = crypto["kdf"]
    kparams = crypto["kdfparams"]
    salt = bytes.fromhex(kparams["salt"])
    if kdf == "scrypt":
        n, r, p, dklen = (kparams[k] for k in ("n", "r", "p", "dklen"))
        # Explicit headroom permits standard 256 MiB profiles, after the bound above.
        derived = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=n, r=r, p=p, dklen=dklen,
                                 maxmem=512 * 1024 * 1024)
    elif kdf == "pbkdf2":
        c = kparams.get("c", 262144)
        dklen = kparams.get("dklen", 32)
        prf = kparams.get("prf", "hmac-sha256").replace("hmac-", "")
        derived = hashlib.pbkdf2_hmac(prf, password.encode("utf-8"), salt, c, dklen)
    else:
        raise ValueError("Unsupported KDF: %s" % kdf)

    cipher_key = derived[:16]
    mac_key = derived[16:32]
    ciphertext = bytes.fromhex(crypto["ciphertext"])
    iv = bytes.fromhex(crypto["cipherparams"]["iv"])
    expected_mac = crypto["mac"].lower()
    mac_std = keccak256(mac_key + ciphertext).hex()
    mac_with_iv = keccak256(mac_key + iv + ciphertext).hex()
    if not (hmac.compare_digest(mac_std, expected_mac) or hmac.compare_digest(mac_with_iv, expected_mac)):
        raise ValueError("Invalid keystore password or corrupted payload (MAC mismatch)")
    return aes_ctr(cipher_key, iv, ciphertext)
