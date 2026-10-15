"""Native custody AES regression tests using only public disposable fixtures."""
import copy
import hashlib
import json
from pathlib import Path
import sys
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
from rh import crypto as C
KEY=bytes(range(16));IV=bytes(range(16,32));DATA=b'public disposable native AES fixture'
NIST_PLAIN=bytes.fromhex('6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710')
NIST_IV=bytes.fromhex('f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff')
NIST=[('2b7e151628aed2a6abf7158809cf4f3c','874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee'),
 ('8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b','1abc932417521ca24f2b0459fe7e6e0b090339ec0aa6faefd5ccc2c6f4ce8e941e36b26bd1ebc670d1bd1d665620abf74f78a7f6d29809585a97daec58c6b050'),
 ('603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4','601ec313775789a5b7a7f504bbf3d228f443e3ca4d62b59aca84e990cacaf5c52b0930daa23de94ce87017ba2d84988ddfc9c58db67aada613c2dd08457941a6')]

class NativeAESRoutingTests(unittest.TestCase):
    def test_no_python_AES_rounds_or_key_schedule(self):
        expected=C.aes_ctr(KEY,IV,DATA)
        with patch.object(C,'aes_key_expansion',side_effect=AssertionError('Python AES schedule forbidden'),create=True),patch.object(C,'aes_encrypt_block',side_effect=AssertionError('Python AES rounds forbidden'),create=True):self.assertEqual(C.aes_ctr(KEY,IV,DATA),expected)
    def test_missing_backend_blocks_without_fallback(self):
        with patch.object(C,'_native_aes_backend',side_effect=RuntimeError('Native backend unavailable'),create=True),self.assertRaises(RuntimeError):C.aes_ctr(KEY,IV,DATA)
    def test_backend_failure_blocks_even_empty_payload(self):
        with patch.object(C,'_native_aes_backend',side_effect=RuntimeError('Native backend unavailable'),create=True),self.assertRaises(RuntimeError):C.aes_ctr(KEY,IV,b'')
    def test_invalid_inputs_rejected_before_backend(self):
        for key,iv,data in ((b'',IV,DATA),(b'x'*15,IV,DATA),(b'x'*17,IV,DATA),(KEY,b'x'*15,DATA),(KEY,b'x'*17,DATA),(KEY,IV,'plaintext'),('key',IV,DATA),(KEY,True,DATA)):
            with self.subTest(types=(type(key).__name__,type(iv).__name__,type(data).__name__)),patch.object(C,'_native_aes_backend',side_effect=AssertionError('Backend must not execute'),create=True),self.assertRaises(ValueError):C.aes_ctr(key,iv,data)
    def test_encryption_requires_backend_before_KDF(self):
        with patch.object(C,'_native_aes_backend',side_effect=RuntimeError('Backend unavailable'),create=True),patch.object(C.hashlib,'scrypt',side_effect=AssertionError('Must not derive')),self.assertRaises(RuntimeError):C.encrypt_keystore(DATA,'public-fixture-password')
    def test_NIST_all_key_sizes_and_directions(self):
        for key,cipher in NIST:
            with self.subTest(bits=len(key)*4):
                expected=bytes.fromhex(cipher);k=bytes.fromhex(key)
                self.assertEqual(C.aes_ctr(k,NIST_IV,NIST_PLAIN),expected)
                self.assertEqual(C.aes_ctr(k,NIST_IV,expected),NIST_PLAIN)
    def test_mutable_inputs_preserved(self):
        key,iv,data=bytearray(KEY),bytearray(IV),bytearray(DATA)
        expected=(bytes(key),bytes(iv),bytes(data))
        self.assertEqual(C.aes_ctr(key,iv,data),C.aes_ctr(*expected));self.assertEqual((bytes(key),bytes(iv),bytes(data)),expected)
    def test_both_keystore_KDFs_still_recover(self):
        for kdf in ('scrypt','pbkdf2'):
            with self.subTest(kdf=kdf):
                envelope=C.encrypt_keystore(DATA,'public-fixture-password',kdf)
                self.assertEqual(C.decrypt_keystore(envelope,'public-fixture-password'),DATA)
    def test_bad_MAC_never_reaches_AES(self):
        envelope=C.encrypt_keystore(DATA,'public-fixture-password');envelope['crypto']['mac']='00'*32
        with patch.object(C,'aes_ctr',side_effect=AssertionError('Do not decrypt unauthenticated ciphertext')),self.assertRaises(ValueError):C.decrypt_keystore(envelope,'public-fixture-password')
    def test_legacy_MAC_with_IV_still_recovers(self):
        password='public-fixture-password';envelope=C.encrypt_keystore(DATA,password);crypt=envelope['crypto'];p=crypt['kdfparams']
        derived=hashlib.scrypt(password.encode(),salt=bytes.fromhex(p['salt']),n=p['n'],r=p['r'],p=p['p'],dklen=32)
        crypt['mac']=C.keccak256(derived[16:]+bytes.fromhex(crypt['cipherparams']['iv'])+bytes.fromhex(crypt['ciphertext'])).hex()
        self.assertEqual(C.decrypt_keystore(envelope,password),DATA)

if __name__=='__main__':unittest.main(verbosity=2)
