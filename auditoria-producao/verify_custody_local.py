"""Operator-only, read-only encrypted backup verification. Never prints keys.

No default wallet paths. Run manually with --primary and --backup; password is
entered locally. This utility neither signs nor uses RPC or restores plaintext.
"""
import argparse
import getpass
import json
import os
from pathlib import Path
import stat
import sys

ROOT = Path(__file__).resolve().parent
if not (ROOT / "rh").is_dir(): ROOT = ROOT.parent
sys.path.insert(0, str(ROOT))
from rh import crypto as C

def _unique_object(pairs):
    result={}
    for key,value in pairs:
        if key in result:raise ValueError('Duplicate custody JSON member')
        result[key]=value
    return result

def _read_encrypted(path):
    # Reject FIFOs/devices after opening without waiting for another process.
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as f:
        info = os.fstat(f.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_uid != os.geteuid():
            raise ValueError("Encrypted backup must be a private, operator-owned regular file")
        content = f.read(16 * 1024 * 1024 + 1)
        if len(content) > 16 * 1024 * 1024:
            raise ValueError("Encrypted backup exceeds verification size limit")
    envelope = json.loads(content,object_pairs_hook=_unique_object)
    if not isinstance(envelope, dict) or envelope.get("version") != 3 or "crypto" not in envelope:
        raise ValueError("Only encrypted wallet collections are accepted")
    return envelope, (info.st_dev, info.st_ino)

def verify_backup(primary, backup, password):
    if not isinstance(password,str) or not password:
        raise ValueError('A nonempty local password is required')
    first, first_id = _read_encrypted(primary)
    second, second_id = _read_encrypted(backup)
    if first_id == second_id:
        raise ValueError("Provide a distinct encrypted backup copy")
    raw = C.decrypt_keystore(first, password)
    restored = C.decrypt_keystore(second, password)
    if raw != restored:
        raise ValueError("Backup does not recover the same wallet collection")
    wallets = json.loads(raw,object_pairs_hook=_unique_object)
    if not isinstance(wallets, list) or not wallets:
        raise ValueError("Invalid recovered wallet collection")
    addresses = set()
    for wallet in wallets:
        if not isinstance(wallet, dict) or not isinstance(wallet.get("priv"), str) or not isinstance(wallet.get("addr"), str):
            raise ValueError("Invalid recovered wallet entry")
        secret = wallet["priv"]
        if not secret.startswith("0x") or not 1 <= len(secret[2:]) <= 64 or any(ch not in "0123456789abcdefABCDEF" for ch in secret[2:]):
            raise ValueError("Invalid recovered private scalar")
        scalar = int(secret, 16)
        if not 1 <= scalar < C.N or C.priv_to_address(scalar) != wallet["addr"].lower():
            raise ValueError("Recovered public address does not match its private scalar")
        if wallet["addr"].lower() in addresses:
            raise ValueError("Duplicate recovered wallet address")
        addresses.add(wallet["addr"].lower())
    return {"verified": True, "wallet_count": len(wallets), "backup_recovery_matches": True,
        "public_addresses_preserved": True, "private_permissions_verified": True,
        "keys_or_addresses_printed": False, "plaintext_written": False, "signing": False, "network": False}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--primary", type=Path, required=True)
    parser.add_argument("--backup", type=Path, required=True)
    args = parser.parse_args()
    password = getpass.getpass("Local encrypted-backup password: ")
    if not password:
        print("Custody verification failed: a nonempty local password is required.", file=sys.stderr)
        return 1
    try:
        report = verify_backup(args.primary, args.backup, password)
    except Exception:
        # Never include recovered values, keys or exception payloads in output.
        print("Custody verification failed; check password, format, permissions and backup locally.", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2))
    return 0

if __name__ == "__main__": sys.exit(main())
