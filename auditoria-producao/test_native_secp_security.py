"""Native backend failure, provenance, blinding and temporary-buffer tests."""
from concurrent.futures import ThreadPoolExecutor
import hashlib
import importlib.util
from pathlib import Path
import shutil
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parent
if not (ROOT/'rh').is_dir():ROOT=ROOT.parent
sys.path.insert(0,str(ROOT))
from rh import crypto as C,native_secp as N
MSG=hashlib.sha256(b'public disposable native backend fixture').digest()

class NativeSecurityTests(unittest.TestCase):
    def proxy_state(self,**overrides):
        state=N._get_state()
        class Lib:
            def __getattr__(self,name):return overrides.get(name,getattr(state.lib,name))
        return SimpleNamespace(ffi=state.ffi,lib=Lib(),ctx=state.ctx)
    def test_exact_distribution_and_blinded_context(self):
        info=N.backend_info()
        self.assertEqual(info['coincurve'],'21.0.0');self.assertEqual(info['files_integrity_verified'],10)
        self.assertTrue(info['context_randomized']);self.assertFalse(info['Python_private_arithmetic_fallback'])
    def test_wrong_distribution_version_rejected(self):
        with patch.object(N.importlib.metadata,'version',return_value='999'),self.assertRaises(N.NativeBackendError):N._verify_distribution()
    def test_unvalidated_platform_rejected(self):
        with patch.object(N.sys,'platform','linux'),self.assertRaises(N.NativeBackendError):N._verify_distribution()
    def test_modified_package_rejected_before_import(self):
        original=Path(importlib.util.find_spec('coincurve').origin).parent
        with tempfile.TemporaryDirectory(prefix='native-package-public-fixture-') as temp:
            folder=Path(temp)
            for name in N._verify_distribution()['files_sha256']:shutil.copyfile(original/name,folder/name)
            (folder/'__init__.py').write_text("raise AssertionError('Unverified module must never execute')")
            with patch.object(N.importlib.util,'find_spec',return_value=SimpleNamespace(origin=str(folder/'__init__.py'))), \
                 patch.object(N.importlib,'import_module',side_effect=AssertionError('Import must not be reached')) as load:
                with self.assertRaises(N.NativeBackendError):N._new_state()
                load.assert_not_called()
    def test_entropy_failure_blocks_without_exposing_payload(self):
        with patch.object(N.secrets,'token_bytes',side_effect=RuntimeError('synthetic-secret-marker')):
            with self.assertRaises(N.NativeBackendError) as error:N._new_state()
            self.assertNotIn('synthetic-secret-marker',str(error.exception))
    def test_failed_context_randomization_blocks(self):
        state=N._get_state()
        class Lib:
            def __getattr__(self,name):
                if name=='secp256k1_context_randomize':return lambda *a:0
                return getattr(state.lib,name)
        binding=SimpleNamespace(ffi=state.ffi,lib=Lib())
        with patch.object(N,'_load_verified_binding',return_value=binding),self.assertRaises(N.NativeBackendError):N._new_state()
    def test_native_sign_failure_blocks(self):
        state=self.proxy_state(secp256k1_ecdsa_sign_recoverable=lambda *a:0)
        with patch.object(N,'_get_state',return_value=state), \
             patch.object(C,'_rfc6979_k',side_effect=AssertionError('No fallback')),self.assertRaises(N.NativeBackendError):C.sign(MSG,1)
    def test_native_public_generation_failure_blocks(self):
        state=self.proxy_state(secp256k1_ec_pubkey_create=lambda *a:0)
        with patch.object(N,'_get_state',return_value=state), \
             patch.object(C,'point_mul_ladder',side_effect=AssertionError('No fallback')),self.assertRaises(N.NativeBackendError):C.priv_to_pub(1)
    def test_native_serialization_failure_blocks(self):
        state=self.proxy_state(secp256k1_ecdsa_recoverable_signature_serialize_compact=lambda *a:0)
        with patch.object(N,'_get_state',return_value=state),self.assertRaises(N.NativeBackendError):C.sign(MSG,1)
    def test_native_secret_validation_rejects_invalid_values(self):
        for key in (0,C.N,C.N+1,-1,True):
            with self.subTest(kind=type(key).__name__),self.assertRaises(ValueError):N.sign_digest(MSG,key)
    def test_temporary_native_secret_buffer_is_cleared(self):
        state=N._get_state();seen=[]
        def verify(ctx,key):seen.append(key);return state.lib.secp256k1_ec_seckey_verify(ctx,key)
        proxy=self.proxy_state(secp256k1_ec_seckey_verify=verify)
        with patch.object(N,'_get_state',return_value=proxy):C.sign(MSG,1)
        self.assertEqual(bytes(state.ffi.buffer(seen[0],32)),b'\x00'*32)
    def test_process_identity_change_recreates_context(self):
        previous=N._get_state()
        with patch.object(N.os,'getpid',return_value=previous.pid+1):new=N._get_state()
        self.assertNotEqual(previous.ctx,new.ctx);self.assertNotEqual(previous.pid,new.pid)
        self.assertEqual(N._get_state().pid,previous.pid)
    def test_concurrent_signing_matches_serial_results(self):
        expected=C.sign(MSG,1)
        with ThreadPoolExecutor(max_workers=4) as pool:results=list(pool.map(lambda _:C.sign(MSG,1),range(32)))
        self.assertTrue(all(r==expected for r in results))
    def test_after_fork_hook_discards_inherited_lock_and_context(self):
        previous=N._get_state();previous_lock=N._lock
        previous_lock.acquire()
        try:
            N._after_fork()
            self.assertIsNone(N._state);self.assertIsNot(N._lock,previous_lock)
            self.assertNotEqual(N._get_state().ctx,previous.ctx)
        finally:previous_lock.release()

if __name__=='__main__':unittest.main(verbosity=2)
