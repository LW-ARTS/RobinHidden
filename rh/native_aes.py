"""Mandatory pinned native AES-CTR, using PyCA Rust/OpenSSL on this Mac.

The exact distribution is verified before import. Upstream audit history is
not an external security certification of this bridge or its binary image.
"""
import hashlib
import importlib
import importlib.machinery
import importlib.metadata
import importlib.util
import json
import marshal
import os
from pathlib import Path
import platform
import sys
import threading
from types import CodeType,ModuleType,SimpleNamespace

_state=None
_lock=threading.Lock()

class NativeAESError(RuntimeError):
    """Backend failure blocks custody AES; no software fallback is permitted."""

def _fail_closed(exc,message):
    # PyO3 panic exceptions derive from BaseException. Keep human cancellation
    # signals intact while suppressing dependency error payloads on failure.
    if isinstance(exc,(KeyboardInterrupt,SystemExit,GeneratorExit)):raise exc
    raise NativeAESError(message) from None

def validate_inputs(key,iv,data):
    if any(type(value) not in (bytes,bytearray) for value in (key,iv,data)):
        raise ValueError('AES expects byte inputs')
    key,iv,data=bytes(key),bytes(iv),bytes(data)
    if len(key) not in (16,24,32) or len(iv)!=16:
        raise ValueError('AES requires a supported key and exact 16-byte counter')
    return key,iv,data

def _verify_distribution():
    profile=json.loads(Path(__file__).with_name('native_aes_distribution.json').read_text())
    if (sys.platform!=profile['platform'] or platform.machine()!=profile['machine'] or
            list(sys.version_info[:2])!=profile['python'] or sys.implementation.name!=profile['implementation']):
        raise NativeAESError('Unsupported custody AES runtime')
    spec=importlib.util.find_spec('cryptography')
    if not spec or not spec.origin:raise NativeAESError('Native custody AES unavailable')
    root=Path(spec.origin).parent.parent.resolve()
    files={}
    for package in profile['packages']:
        if importlib.metadata.version(package['package'])!=package['version']:
            raise NativeAESError('Custody dependency version mismatch')
        for name,expected in package['files_sha256'].items():
            relative=Path(name)
            if relative.is_absolute() or '..' in relative.parts:raise NativeAESError('Invalid custody distribution profile')
            source=root/relative
            if not source.resolve().is_relative_to(root) or hashlib.sha256(source.read_bytes()).hexdigest()!=expected:
                raise NativeAESError('Custody dependency integrity mismatch')
            if name.endswith('.py'):
                cache=Path(importlib.util.cache_from_source(str(source)))
                if cache.exists():
                    try:
                        cached=marshal.loads(cache.read_bytes()[16:])
                        code=compile(source.read_bytes(),str(source),'exec',dont_inherit=True,optimize=sys.flags.optimize)
                    except Exception:raise NativeAESError('Custody bytecode integrity mismatch') from None
                    if not isinstance(cached,CodeType) or cached!=code:raise NativeAESError('Custody bytecode integrity mismatch')
            files[name]=expected
    return profile,root,files

def _verify_loaded_modules(root,files):
    utils=sys.modules.get('cryptography.utils')
    wrapper=getattr(utils,'_ModuleWithDeprecations',None)
    for name,module in tuple(sys.modules.items()):
        if not (name=='_cffi_backend' or name.split('.')[0] in ('cryptography','cffi','pycparser')):continue
        # The pinned PyCA package registers deprecation wrappers for two source
        # modules. Authenticate their underlying module rather than dropping
        # origin checks when the wrapper intentionally has no __spec__.
        if wrapper is not None and type(module) is wrapper:
            module=module._module
        if not isinstance(module,ModuleType):raise NativeAESError('Custody module identity mismatch')
        spec=getattr(module,'__spec__',None)
        path=Path(module.__file__).resolve() if getattr(module,'__file__',None) else None
        if not spec or not path or not path.is_relative_to(root) or spec.name!=name or not spec.origin or Path(spec.origin).resolve()!=path:
            raise NativeAESError('Custody module origin mismatch')
        relative=str(path.relative_to(root))
        if relative not in files or hashlib.sha256(path.read_bytes()).hexdigest()!=files[relative]:
            raise NativeAESError('Custody loaded module integrity mismatch')
        if path.suffix=='.so' and not isinstance(spec.loader,importlib.machinery.ExtensionFileLoader):
            raise NativeAESError('Custody native loader mismatch')

def _new_state():
    try:
        profile,root,files=_verify_distribution()
        ciphers=importlib.import_module('cryptography.hazmat.primitives.ciphers')
        algorithms=importlib.import_module('cryptography.hazmat.primitives.ciphers.algorithms')
        modes=importlib.import_module('cryptography.hazmat.primitives.ciphers.modes')
        rust=importlib.import_module('cryptography.hazmat.bindings._rust')
        if rust is not sys.modules.get('cryptography.hazmat.bindings._rust'):
            raise NativeAESError('Custody native module identity mismatch')
        _verify_loaded_modules(root,files)
        version=rust.openssl.openssl_version_text()
        if version!=profile['OpenSSL_version']:raise NativeAESError('Unexpected custody OpenSSL version')
        check=ciphers.Cipher(algorithms.AES(bytes(16)),modes.CTR(bytes(16))).encryptor()
        if (type(check) is not rust.openssl.ciphers.CipherContext or
                check.update(bytes(16))+check.finalize()!=bytes.fromhex('66e94bd4ef8a2c3b884cfa59ca342b2e')):
            raise NativeAESError('Custody native AES known-answer check failed')
        return SimpleNamespace(Cipher=ciphers.Cipher,AES=algorithms.AES,CTR=modes.CTR,
            native_context_type=rust.openssl.ciphers.CipherContext,profile=profile,files=files,pid=os.getpid())
    except BaseException as exc:
        _fail_closed(exc,'Native custody AES unavailable or failed runtime/integrity checks')

def _get_state():
    global _state
    with _lock:
        if _state is None or _state.pid!=os.getpid():_state=_new_state()
        return _state

def _after_fork():
    global _state,_lock
    _state=None;_lock=threading.Lock()

if hasattr(os,'register_at_fork'):os.register_at_fork(after_in_child=_after_fork)

def require_backend():
    """Fail before custody KDF/encryption when the native backend is unavailable."""
    _get_state()

def transform(key,iv,data):
    """AES-128/192/256 CTR; a fresh native context for every operation."""
    key,iv,data=validate_inputs(key,iv,data)
    state=_get_state()
    try:
        context=state.Cipher(state.AES(key),state.CTR(iv)).encryptor()
        if type(context) is not state.native_context_type:
            raise NativeAESError('Non-native custody cipher context')
        result=context.update(data)+context.finalize()
        if type(result) is not bytes or len(result)!=len(data):
            raise NativeAESError('Invalid native AES output')
        return result
    except BaseException as exc:
        _fail_closed(exc,'Native custody AES failed; no fallback permitted')

def backend_info():
    state=_get_state()
    return {'backend':'PyCA Rust/OpenSSL AES-CTR','cryptography':state.profile['packages'][0]['version'],
        'OpenSSL':state.profile['OpenSSL_version'],'files_integrity_verified':len(state.files),
        'native_context':'cryptography.hazmat.bindings._rust.openssl.ciphers.CipherContext',
        'startup_known_answer_check':True,'native_only':True,'Python_AES_fallback':False,'external_exact_binary_audit_verified':False,
        'whole_process_constant_time_or_erasure_certified':False}
