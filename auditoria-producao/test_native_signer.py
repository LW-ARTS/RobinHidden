"""Prove native routing and fail-closed behavior with disposable fixture keys."""
import hashlib
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parent
if not (ROOT/'rh').is_dir():ROOT=ROOT.parent
sys.path.insert(0,str(ROOT))
from rh import crypto as C

DIGEST=hashlib.sha256(b'disposable native-signing routing fixture').digest()
class NativeRoutingTests(unittest.TestCase):
    def test_sign_never_uses_Python_secret_arithmetic(self):
        with patch.object(C,'_rfc6979_k',side_effect=AssertionError('Python nonce forbidden')), \
             patch.object(C,'point_mul_ladder',side_effect=AssertionError('Python ladder forbidden')), \
             patch.object(C,'_inv',side_effect=AssertionError('Python inverse forbidden')), \
             patch.object(C,'_mul',side_effect=AssertionError('Python multiplication forbidden')):
            r,s,recid=C.sign(DIGEST,1)
            self.assertTrue(0<r<C.N and 0<s<=C.N//2 and recid in (0,1,2,3))
    def test_public_derivation_never_uses_Python_secret_arithmetic(self):
        with patch.object(C,'point_mul_ladder',side_effect=AssertionError('Python ladder forbidden')), \
             patch.object(C,'_mul',side_effect=AssertionError('Python multiplication forbidden')):
            self.assertEqual(C.priv_to_pub(1),C.G)
    def test_missing_backend_does_not_fall_back(self):
        with patch.object(C,'_native_backend',side_effect=RuntimeError('Native backend unavailable'),create=True):
            for operation in (lambda:C.sign(DIGEST,1),lambda:C.priv_to_pub(1)):
                with self.assertRaises(RuntimeError):operation()
    def test_invalid_private_key_rejected_before_backend(self):
        with patch.object(C,'_native_backend',side_effect=AssertionError('Invalid key must stop earlier'),create=True):
            for value in (0,-1,C.N,True,'1'):
                with self.subTest(kind=type(value).__name__),self.assertRaises(ValueError):C.sign(DIGEST,value)
    def test_invalid_digest_rejected_before_backend(self):
        with patch.object(C,'_native_backend',side_effect=AssertionError('Invalid digest must stop earlier'),create=True):
            for value in (b'',b'\x00'*31,b'\x00'*33,None):
                with self.subTest(kind=type(value).__name__),self.assertRaises(ValueError):C.sign(value,1)

if __name__=='__main__':unittest.main(verbosity=2)
