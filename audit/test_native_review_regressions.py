"""Independent-review regressions: synthetic inputs, no transactions or network."""
import hashlib
import importlib.util
import marshal
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
    if event in ('socket.connect','socket.getaddrinfo'):
        raise PermissionError('Offline review: network blocked')
    if event=='open' and isinstance(args[0],(str,bytes)):
        p=Path(args[0]).resolve()
        if any(p.is_relative_to(ROOT/d) for d in ('data','RHEX/data')):
            raise PermissionError('Operator data blocked')
sys.addaudithook(guard)
from rh import crypto as C,native_secp as N
MSG=hashlib.sha256(b'public native review fixture').digest()
P=2**256-2**32-977

class NativeReviewTests(unittest.TestCase):
    def proxy(self,**overrides):
        state=N._get_state()
        class Lib:
            def __getattr__(self,name):return overrides.get(name,getattr(state.lib,name))
        return SimpleNamespace(ffi=state.ffi,lib=Lib(),ctx=state.ctx)

    def test_signature_result_boundaries_blocked(self):
        state=N._get_state()
        for r,s,recid in ((0,1,0),(C.N,1,0),(1,0,0),(1,C.N//2+1,0),(1,C.N,0),(1,1,-1),(1,1,4)):
            def serialize(ctx,out,recovery,sig):
                state.ffi.memmove(out,r.to_bytes(32,'big')+s.to_bytes(32,'big'),64)
                recovery[0]=recid
                return 1
            proxy=self.proxy(secp256k1_ecdsa_recoverable_signature_serialize_compact=serialize)
            with self.subTest(r=r,s=s,recid=recid),patch.object(N,'_get_state',return_value=proxy),self.assertRaises(N.NativeBackendError):
                N.sign_digest(MSG,1)

    def test_signature_valid_range_wrong_key_message_blocked(self):
        state=N._get_state()
        wrong=N.sign_digest(hashlib.sha256(b'different public message').digest(),2)
        for signature in ((1,1,0),wrong):
            def serialize(ctx,out,recovery,sig):
                r,s,recid=signature
                state.ffi.memmove(out,r.to_bytes(32,'big')+s.to_bytes(32,'big'),64);recovery[0]=recid
                return 1
            proxy=self.proxy(secp256k1_ecdsa_recoverable_signature_serialize_compact=serialize)
            with self.subTest(signature=signature),patch.object(N,'_get_state',return_value=proxy),self.assertRaises(N.NativeBackendError):N.sign_digest(MSG,1)

    def test_recovery_failure_blocks(self):
        proxy=self.proxy(secp256k1_ecdsa_recover=lambda *a:0)
        with patch.object(N,'_get_state',return_value=proxy),self.assertRaises(N.NativeBackendError):N.sign_digest(MSG,1)

    def test_parse_failure_blocks(self):
        proxy=self.proxy(secp256k1_ecdsa_recoverable_signature_parse_compact=lambda *a:0)
        with patch.object(N,'_get_state',return_value=proxy),self.assertRaises(N.NativeBackendError):N.sign_digest(MSG,1)

    def test_digest_subclass_cannot_lie_about_length(self):
        class Misleading(bytes):
            def __len__(self):return 32
        with patch.object(N,'_get_state',side_effect=AssertionError('Backend must not be reached')),self.assertRaises(ValueError):
            N.sign_digest(Misleading(b'a'),1)

    def test_mutable_digest_is_snapshotted_once(self):
        state=N._get_state();mutable=bytearray(MSG);expected=N.sign_digest(MSG,1)
        def signing(ctx,sig,msg,key,*args):
            mutable[:]=b'\xff'*32
            return state.lib.secp256k1_ecdsa_sign_recoverable(ctx,sig,msg,key,*args)
        proxy=self.proxy(secp256k1_ecdsa_sign_recoverable=signing)
        with patch.object(N,'_get_state',return_value=proxy):self.assertEqual(N.sign_digest(mutable,1),expected)

    def test_preloaded_wrong_binding_origin_blocked(self):
        N._get_state()
        real=sys.modules['coincurve._libsecp256k1']
        fake=ModuleType(real.__name__);fake.ffi=real.ffi;fake.lib=real.lib
        fake.__file__='/private/tmp/unverified-public-fixture.so';fake.__spec__=real.__spec__
        with patch.dict(sys.modules,{'coincurve._libsecp256k1':fake}),self.assertRaises(N.NativeBackendError):N._new_state()

    def test_preloaded_wrong_cffi_origin_blocked(self):
        N._get_state()
        real=sys.modules['coincurve._cffi_backend']
        fake=ModuleType(real.__name__);fake.__file__='/private/tmp/unverified-public-fixture.so';fake.__spec__=real.__spec__
        with patch.dict(sys.modules,{'coincurve._cffi_backend':fake}),self.assertRaises(N.NativeBackendError):N._new_state()

    def test_unverified_import_result_blocked(self):
        with patch.object(N.importlib,'import_module',return_value=SimpleNamespace(ffi=None,lib=None)),self.assertRaises(N.NativeBackendError):N._new_state()

    def test_forged_timestamp_valid_bytecode_blocked(self):
        self.cache_case(forged=True)

    def test_source_equivalent_bytecode_allowed(self):
        self.cache_case(forged=False)

    def cache_case(self,forged):
        original=Path(importlib.util.find_spec('coincurve').origin).parent
        profile=N._verify_distribution()
        with tempfile.TemporaryDirectory(prefix='native-bytecode-public-fixture-') as temp:
            folder=Path(temp)
            for name in profile['files_sha256']:shutil.copyfile(original/name,folder/name)
            source=folder/'__init__.py';cache=Path(importlib.util.cache_from_source(str(source)));cache.parent.mkdir()
            content=b"raise AssertionError('Unverified cache must never execute')" if forged else source.read_bytes()
            code=compile(content,str(source),'exec',dont_inherit=True,optimize=sys.flags.optimize)
            # Header timestamp/size intentionally matches the pinned source.
            from importlib._bootstrap_external import _code_to_timestamp_pyc
            cache.write_bytes(_code_to_timestamp_pyc(code,int(source.stat().st_mtime),source.stat().st_size))
            with patch.object(N.importlib.util,'find_spec',return_value=SimpleNamespace(origin=str(source))):
                if forged:
                    with self.assertRaises(N.NativeBackendError):N._verify_distribution()
                else:self.assertEqual(N._verify_distribution(),profile)

    def assert_bad_point(self,x,y,prefix=4,length=65):
        state=N._get_state()
        def serialize(ctx,out,size,pubkey,flags):
            state.ffi.memmove(out,bytes([prefix])+x.to_bytes(32,'big')+y.to_bytes(32,'big'),65)
            size[0]=length
            return 1
        proxy=self.proxy(secp256k1_ec_pubkey_serialize=serialize)
        with patch.object(N,'_get_state',return_value=proxy),self.assertRaises(N.NativeBackendError):N.public_point(1)

    def test_public_point_out_of_field_blocked(self):self.assert_bad_point(P,1)
    def test_public_point_y_out_of_field_blocked(self):self.assert_bad_point(1,P)
    def test_public_point_off_curve_blocked(self):self.assert_bad_point(0,0)
    def test_public_point_bad_prefix_blocked(self):self.assert_bad_point(1,1,prefix=2)
    def test_public_point_bad_length_blocked(self):self.assert_bad_point(1,1,length=64)

    def test_secret_buffer_cleared_on_sign_failure(self):
        state=N._get_state();seen=[]
        def fail(ctx,sig,msg,key,*args):seen.append(key);return 0
        proxy=self.proxy(secp256k1_ecdsa_sign_recoverable=fail)
        with patch.object(N,'_get_state',return_value=proxy),self.assertRaises(N.NativeBackendError):N.sign_digest(MSG,1)
        self.assertEqual(bytes(state.ffi.buffer(seen[0],32)),b'\0'*32)

    def test_secret_buffer_cleared_on_public_generation_failure(self):
        state=N._get_state();seen=[]
        def fail(ctx,pubkey,key):seen.append(key);return 0
        proxy=self.proxy(secp256k1_ec_pubkey_create=fail)
        with patch.object(N,'_get_state',return_value=proxy),self.assertRaises(N.NativeBackendError):N.public_point(1)
        self.assertEqual(bytes(state.ffi.buffer(seen[0],32)),b'\0'*32)

    def test_actual_fork_replaces_inherited_locked_state(self):
        expected=N.sign_digest(MSG,1);parent=N._get_state();lock=N._lock
        reader,writer=os.pipe();lock.acquire();pid=None
        try:
            pid=os.fork()
            if pid==0:
                os.close(reader)
                try:
                    new=N._get_state()
                    ok=(new.pid==os.getpid() and new.pid!=parent.pid and new.ctx!=parent.ctx and N.sign_digest(MSG,1)==expected)
                    os.write(writer,b'PASS' if ok else b'FAIL')
                    os._exit(0 if ok else 1)
                except BaseException:
                    os.write(writer,b'FAIL');os._exit(1)
            os.close(writer);writer=None
            if not select.select([reader],[],[],5)[0]:
                os.kill(pid,9);self.fail('Child blocked on inherited state')
            self.assertEqual(os.read(reader,4),b'PASS')
            _,status=os.waitpid(pid,0);pid=None
            self.assertEqual(os.waitstatus_to_exitcode(status),0)
        finally:
            lock.release();os.close(reader)
            if writer is not None:os.close(writer)
            if pid is not None:
                os.kill(pid,9);os.waitpid(pid,0)

if __name__=='__main__':unittest.main(verbosity=2)
