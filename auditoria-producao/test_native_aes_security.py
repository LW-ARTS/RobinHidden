"""Pinned native AES identity/failure/lifecycle tests; public fixtures only."""
from concurrent.futures import ThreadPoolExecutor
import importlib.util
import os
from pathlib import Path
import select
import shutil
import sys
import tempfile
from types import ModuleType,SimpleNamespace
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parent
if not (ROOT/'rh').is_dir():ROOT=ROOT.parent
sys.path.insert(0,str(ROOT))
def guard(event,args):
    if event.startswith('socket.'):raise PermissionError('Offline AES tests: network blocked')
    if event=='open' and isinstance(args[0],(str,bytes)):
        p=Path(args[0]).resolve()
        if any(p.is_relative_to(ROOT/d) for d in ('data','RHEX/data')):raise PermissionError('Operator data blocked')
sys.addaudithook(guard)
from rh import native_aes as N
KEY=bytes(range(16));IV=bytes(range(16,32));DATA=b'public native AES security fixture'

class NativeAESSecurityTests(unittest.TestCase):
    def test_exact_versions_files_native_type(self):
        info=N.backend_info();self.assertEqual(info['cryptography'],'50.0.2');self.assertEqual(info['OpenSSL'],'OpenSSL 4.0.3 29 Sep 2026')
        self.assertEqual(info['files_integrity_verified'],107);self.assertFalse(info['Python_AES_fallback']);self.assertFalse(info['external_exact_binary_audit_verified'])
    def test_unsupported_runtime_rejects(self):
        with patch.object(N.sys,'platform','linux'),self.assertRaises(N.NativeAESError):N._new_state()
    def test_wrong_dependency_version_rejects(self):
        with patch.object(N.importlib.metadata,'version',return_value='999'),self.assertRaises(N.NativeAESError):N._new_state()
    def test_disk_tampering_blocks_before_import(self):
        profile,root,files=N._verify_distribution()
        with tempfile.TemporaryDirectory(prefix='native-aes-package-fixture-') as temp:
            folder=Path(temp)
            for name in files:
                target=folder/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(root/name,target)
            (folder/'cryptography/__init__.py').write_text("raise AssertionError('Unverified package must not execute')")
            with patch.object(N.importlib.util,'find_spec',return_value=SimpleNamespace(origin=str(folder/'cryptography/__init__.py'))),patch.object(N.importlib,'import_module',side_effect=AssertionError('Must not import')) as load,self.assertRaises(N.NativeAESError):N._new_state()
            load.assert_not_called()
    def test_forged_timestamp_cache_rejects(self):
        profile,root,files=N._verify_distribution()
        with tempfile.TemporaryDirectory(prefix='native-aes-cache-fixture-') as temp:
            folder=Path(temp)
            for name in files:
                target=folder/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(root/name,target)
            source=folder/'cryptography/__init__.py';cache=Path(importlib.util.cache_from_source(str(source)));cache.parent.mkdir()
            from importlib._bootstrap_external import _code_to_timestamp_pyc
            code=compile("raise AssertionError('Forged cache must not execute')",str(source),'exec')
            cache.write_bytes(_code_to_timestamp_pyc(code,int(source.stat().st_mtime),source.stat().st_size))
            with patch.object(N.importlib.util,'find_spec',return_value=SimpleNamespace(origin=str(source))),self.assertRaises(N.NativeAESError):N._new_state()
    def test_substituted_rust_module_origin_rejects(self):
        N._get_state();name='cryptography.hazmat.bindings._rust';real=sys.modules[name];fake=ModuleType(name)
        fake.__file__='/private/tmp/unverified-public-fixture.so';fake.__spec__=real.__spec__;fake.openssl=real.openssl
        with patch.dict(sys.modules,{name:fake}),self.assertRaises(N.NativeAESError):N._new_state()
    def test_substituted_cffi_module_origin_rejects(self):
        N._get_state();real=sys.modules['_cffi_backend'];fake=ModuleType('_cffi_backend');fake.__file__='/private/tmp/unverified-public-fixture.so';fake.__spec__=real.__spec__
        with patch.dict(sys.modules,{'_cffi_backend':fake}),self.assertRaises(N.NativeAESError):N._new_state()
    def test_deprecation_wrapper_with_wrong_underlying_origin_rejects(self):
        N._get_state();utils=sys.modules['cryptography.utils'];name='cryptography.hazmat.primitives.ciphers.modes'
        real=sys.modules[name]._module;fake=ModuleType(name);fake.__file__='/private/tmp/unverified-public-fixture.py';fake.__spec__=real.__spec__
        with patch.dict(sys.modules,{name:utils._ModuleWithDeprecations(fake)}),self.assertRaises(N.NativeAESError):N._new_state()
    def fake_state(self,context,context_type=None):
        state=N._get_state()
        class Cipher:
            def __init__(self,*args):pass
            def encryptor(self):return context
        return SimpleNamespace(Cipher=Cipher,AES=state.AES,CTR=state.CTR,native_context_type=context_type or state.native_context_type)
    def test_non_native_context_rejects(self):
        fake=SimpleNamespace(update=lambda data:data,finalize=lambda:b'')
        with patch.object(N,'_get_state',return_value=self.fake_state(fake)),self.assertRaises(N.NativeAESError):N.transform(KEY,IV,DATA)
    def test_native_update_error_is_sanitized(self):
        class Context:
            def update(self,data):raise RuntimeError('public-synthetic-secret-marker')
            def finalize(self):return b''
        with patch.object(N,'_get_state',return_value=self.fake_state(Context(),Context)),self.assertRaises(N.NativeAESError) as error:N.transform(KEY,IV,DATA)
        self.assertNotIn('public-synthetic-secret-marker',str(error.exception));self.assertTrue(error.exception.__suppress_context__)
    def test_native_finalization_error_is_sanitized(self):
        class Context:
            def update(self,data):return data
            def finalize(self):raise RuntimeError('public-synthetic-secret-marker')
        with patch.object(N,'_get_state',return_value=self.fake_state(Context(),Context)),self.assertRaises(N.NativeAESError) as error:N.transform(KEY,IV,DATA)
        self.assertNotIn('public-synthetic-secret-marker',str(error.exception))
    def test_panic_like_base_exception_is_sanitized(self):
        class PanicFixture(BaseException):pass
        class Context:
            def update(self,data):raise PanicFixture('public-synthetic-secret-marker')
            def finalize(self):return b''
        with patch.object(N,'_get_state',return_value=self.fake_state(Context(),Context)),self.assertRaises(N.NativeAESError) as error:N.transform(KEY,IV,DATA)
        self.assertNotIn('public-synthetic-secret-marker',str(error.exception));self.assertTrue(error.exception.__suppress_context__)
    def test_user_cancellation_is_preserved(self):
        for signal in (KeyboardInterrupt,SystemExit,GeneratorExit):
            class Context:
                def update(self,data):raise signal()
                def finalize(self):return b''
            with self.subTest(signal=signal.__name__),patch.object(N,'_get_state',return_value=self.fake_state(Context(),Context)),self.assertRaises(signal):N.transform(KEY,IV,DATA)
    def test_short_native_output_rejects(self):
        class Context:
            def update(self,data):return b''
            def finalize(self):return b''
        with patch.object(N,'_get_state',return_value=self.fake_state(Context(),Context)),self.assertRaises(N.NativeAESError):N.transform(KEY,IV,DATA)
    def test_subclass_input_rejects_before_native_load(self):
        class Misleading(bytes):
            def __len__(self):return 16
        with patch.object(N,'_get_state',side_effect=AssertionError('Must not load')),self.assertRaises(ValueError):N.transform(Misleading(b'x'),IV,DATA)
    def test_each_operation_has_a_fresh_context(self):
        state=N._get_state();seen=[]
        class Cipher:
            def __init__(self,*args):self.cipher=state.Cipher(*args)
            def encryptor(self):
                ctx=self.cipher.encryptor();seen.append(ctx);return ctx
        proxy=SimpleNamespace(Cipher=Cipher,AES=state.AES,CTR=state.CTR,native_context_type=state.native_context_type)
        with patch.object(N,'_get_state',return_value=proxy):a=N.transform(KEY,IV,DATA);b=N.transform(KEY,IV,DATA)
        self.assertEqual(a,b);self.assertIsNot(seen[0],seen[1])
    def test_concurrent_results_match_serial(self):
        expected=N.transform(KEY,IV,DATA)
        with ThreadPoolExecutor(max_workers=4) as pool:results=list(pool.map(lambda _:N.transform(KEY,IV,DATA),range(32)))
        self.assertEqual(results,[expected]*32)
    def test_actual_fork_with_inherited_lock(self):
        expected=N.transform(KEY,IV,DATA);previous=N._get_state();lock=N._lock;reader,writer=os.pipe();pid=None;lock.acquire()
        try:
            pid=os.fork()
            if pid==0:
                os.close(reader)
                try:
                    state=N._get_state();ok=state.pid==os.getpid() and state.pid!=previous.pid and N.transform(KEY,IV,DATA)==expected
                    os.write(writer,b'PASS' if ok else b'FAIL');os._exit(0 if ok else 1)
                except BaseException:os.write(writer,b'FAIL');os._exit(1)
            os.close(writer);writer=None
            if not select.select([reader],[],[],5)[0]:os.kill(pid,9);self.fail('Inherited AES lock blocks child')
            self.assertEqual(os.read(reader,4),b'PASS');_,status=os.waitpid(pid,0);pid=None;self.assertEqual(os.waitstatus_to_exitcode(status),0)
        finally:
            lock.release();os.close(reader)
            if writer is not None:os.close(writer)
            if pid is not None:os.kill(pid,9);os.waitpid(pid,0)

if __name__=='__main__':unittest.main(verbosity=2)
