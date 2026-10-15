"""Mandatory native secp256k1 private operations; no Python signing fallback.

The validated distribution is Coincurve 21.0.0 / upstream libsecp256k1 0.6.0
on macOS arm64 CPython 3.12. Package files are checked before first import.
Only digest signing and public-key generation are exposed here.
"""
from contextlib import contextmanager
import hashlib
import importlib
import importlib.metadata
import importlib.machinery
import importlib.util
import json
import marshal
import os
from pathlib import Path
import platform
import secrets
import sys
import threading
from types import CodeType,ModuleType,SimpleNamespace

N=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
P=2**256-2**32-977
_state=None
_lock=threading.Lock()

class NativeBackendError(RuntimeError):
    """A missing, unsupported or failed native backend blocks private operations."""

def _verify_distribution():
    profile=json.loads(Path(__file__).with_name('native_secp_distribution.json').read_text())
    if (sys.platform!=profile['platform'] or platform.machine()!=profile['machine'] or
            list(sys.version_info[:2])!=profile['python'] or sys.implementation.name!='cpython'):
        raise NativeBackendError('Unsupported native signer runtime; use the verified project environment')
    if importlib.metadata.version('coincurve')!=profile['coincurve_version']:
        raise NativeBackendError('Native signer distribution version mismatch')
    spec=importlib.util.find_spec('coincurve')
    if not spec or not spec.origin:raise NativeBackendError('Native signer distribution unavailable')
    folder=Path(spec.origin).parent
    for name,expected in profile['files_sha256'].items():
        if Path(name).name!=name or hashlib.sha256((folder/name).read_bytes()).hexdigest()!=expected:
            raise NativeBackendError('Native signer distribution integrity mismatch')
        if name.endswith('.py'):
            source=folder/name
            cache=Path(importlib.util.cache_from_source(str(source)))
            if cache.exists():
                # Python may execute a timestamp-valid cache instead of the hashed
                # source. Compare code semantics, not only cache timestamp/size.
                try:
                    cached=marshal.loads(cache.read_bytes()[16:])
                    expected_code=compile(source.read_bytes(),str(source),'exec',dont_inherit=True,optimize=sys.flags.optimize)
                except Exception:
                    raise NativeBackendError('Native signer bytecode integrity mismatch') from None
                if not isinstance(cached,CodeType) or cached!=expected_code:
                    raise NativeBackendError('Native signer bytecode integrity mismatch')
    return profile

def _load_verified_binding(profile):
    folder=Path(importlib.util.find_spec('coincurve').origin).parent.resolve()
    binding=importlib.import_module('coincurve._libsecp256k1')
    if binding is not sys.modules.get('coincurve._libsecp256k1'):
        raise NativeBackendError('Native signer loaded module identity mismatch')
    for module_name,prefix in (('coincurve._libsecp256k1','_libsecp256k1.'),('coincurve._cffi_backend','_cffi_backend.')):
        module=sys.modules.get(module_name)
        names=[n for n in profile['files_sha256'] if n.startswith(prefix) and n.endswith('.so')]
        if len(names)!=1 or not isinstance(module,ModuleType):
            raise NativeBackendError('Native signer loaded module identity mismatch')
        expected=folder/names[0];spec=getattr(module,'__spec__',None)
        if (not spec or spec.name!=module_name or not isinstance(spec.loader,importlib.machinery.ExtensionFileLoader)
                or Path(module.__file__).resolve()!=expected or Path(spec.origin).resolve()!=expected
                or hashlib.sha256(expected.read_bytes()).hexdigest()!=profile['files_sha256'][names[0]]):
            raise NativeBackendError('Native signer loaded module identity mismatch')
    return binding

def _new_state():
    try:
        profile=_verify_distribution()
        binding=_load_verified_binding(profile)
        ffi,lib=binding.ffi,binding.lib
        ctx=ffi.gc(lib.secp256k1_context_create(lib.SECP256K1_CONTEXT_NONE),lib.secp256k1_context_destroy)
        if ctx==ffi.NULL:raise NativeBackendError('Native signer context unavailable')
        seed=ffi.new('unsigned char[32]',secrets.token_bytes(32))
        try:
            if lib.secp256k1_context_randomize(ctx,seed)!=1:
                raise NativeBackendError('Native signer context randomization failed')
        finally:ffi.memmove(seed,b'\x00'*32,32)
        return SimpleNamespace(ffi=ffi,lib=lib,ctx=ctx,pid=os.getpid(),profile=profile)
    except Exception:
        # Never include secret-dependent exception payloads or import tracebacks.
        raise NativeBackendError('Native signer unavailable, unsupported or failed integrity/randomization checks') from None

def _get_state():
    global _state
    with _lock:
        if _state is None or _state.pid!=os.getpid():_state=_new_state()
        return _state

def _after_fork():
    global _state,_lock
    _state=None;_lock=threading.Lock()

if hasattr(os,'register_at_fork'):os.register_at_fork(after_in_child=_after_fork)

@contextmanager
def _secret_buffer(state,private_scalar):
    if type(private_scalar) is not int:raise ValueError('Invalid native private scalar')
    try:raw=bytearray(private_scalar.to_bytes(32,'big'))
    except (OverflowError,ValueError):raise ValueError('Invalid native private scalar') from None
    buf=None
    try:
        buf=state.ffi.new('unsigned char[32]',bytes(raw))
        if state.lib.secp256k1_ec_seckey_verify(state.ctx,buf)!=1:
            raise ValueError('Invalid native private scalar')
        yield buf
    finally:
        raw[:]=b'\x00'*32
        if buf is not None:state.ffi.memmove(buf,b'\x00'*32,32)

def sign_digest(digest,private_scalar):
    """Native default RFC6979 nonce, secret scalar arithmetic and low-S ECDSA."""
    if type(digest) not in (bytes,bytearray):
        raise ValueError('Expected an exact 32-byte message digest')
    digest=bytes(digest)
    if len(digest)!=32:raise ValueError('Expected an exact 32-byte message digest')
    state=_get_state();ffi,lib=state.ffi,state.lib
    try:
        with _secret_buffer(state,private_scalar) as key:
            signature=ffi.new('secp256k1_ecdsa_recoverable_signature *')
            if lib.secp256k1_ecdsa_sign_recoverable(state.ctx,signature,digest,key,ffi.NULL,ffi.NULL)!=1:
                raise NativeBackendError('Native signing failed')
            compact=ffi.new('unsigned char[64]');recid=ffi.new('int *')
            if lib.secp256k1_ecdsa_recoverable_signature_serialize_compact(state.ctx,compact,recid,signature)!=1:
                raise NativeBackendError('Native signature serialization failed')
            encoded=bytes(ffi.buffer(compact,64));r=int.from_bytes(encoded[:32],'big');s=int.from_bytes(encoded[32:],'big')
            if not (0<r<N and 0<s<=N//2 and recid[0] in (0,1,2,3)):
                raise NativeBackendError('Invalid native signature result')
            # Check the serialized result against this message/key, using only
            # native recovery and native private public-key generation.
            parsed=ffi.new('secp256k1_ecdsa_recoverable_signature *')
            recovered=ffi.new('secp256k1_pubkey *')
            if (lib.secp256k1_ecdsa_recoverable_signature_parse_compact(state.ctx,parsed,compact,recid[0])!=1
                    or lib.secp256k1_ecdsa_recover(state.ctx,recovered,parsed,digest)!=1
                    or _serialize_public(state,recovered)!=_public_encoding(state,key)):
                raise NativeBackendError('Native signature message/key mismatch')
            return r,s,recid[0]
    except ValueError:raise ValueError('Invalid native signing input') from None
    except Exception:raise NativeBackendError('Native signing failed; no fallback permitted') from None

def _serialize_public(state,pubkey):
    ffi,lib=state.ffi,state.lib
    output=ffi.new('unsigned char[65]');length=ffi.new('size_t *',65)
    if lib.secp256k1_ec_pubkey_serialize(state.ctx,output,length,pubkey,lib.SECP256K1_EC_UNCOMPRESSED)!=1 or length[0]!=65:
        raise NativeBackendError('Native public-key serialization failed')
    encoded=bytes(ffi.buffer(output,65))
    x,y=int.from_bytes(encoded[1:33],'big'),int.from_bytes(encoded[33:],'big')
    # These are public coordinates, never Python private scalar arithmetic.
    if encoded[0]!=4 or x>=P or y>=P or (y*y-x*x*x-7)%P!=0:
        raise NativeBackendError('Invalid native public-key result')
    return encoded

def _public_encoding(state,key):
    pubkey=state.ffi.new('secp256k1_pubkey *')
    if state.lib.secp256k1_ec_pubkey_create(state.ctx,pubkey,key)!=1:
        raise NativeBackendError('Native public-key generation failed')
    return _serialize_public(state,pubkey)

def public_point(private_scalar):
    """Generate the public point without Python private scalar multiplication."""
    state=_get_state()
    try:
        with _secret_buffer(state,private_scalar) as key:
            encoded=_public_encoding(state,key)
            return int.from_bytes(encoded[1:33],'big'),int.from_bytes(encoded[33:],'big')
    except ValueError:raise ValueError('Invalid native public-key input') from None
    except Exception:raise NativeBackendError('Native public-key generation failed; no fallback permitted') from None

def backend_info():
    state=_get_state()
    return {'backend':'libsecp256k1 via Coincurve CFFI','coincurve':state.profile['coincurve_version'],
        'upstream_libsecp256k1':state.profile['libsecp256k1_upstream_version'],'wheel_sha256':state.profile['wheel_sha256'],
        'files_integrity_verified':len(state.profile['files_sha256']),'context_randomized':True,
        'native_only':True,'Python_private_arithmetic_fallback':False,'external_exact_binary_audit_verified':False}
