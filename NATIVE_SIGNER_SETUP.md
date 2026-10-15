# Verified native signer environment

Date: 2026-10-13. Tested target: this Mac, macOS arm64, CPython 3.12.

Private ECDSA signing and public-key generation now require the native
libsecp256k1 backend through Coincurve 21.0.0. The current verified environment
is `.venv-signer`. Its installation is isolated from the system Python.

Use this interpreter for local validation:

```sh
.venv-signer/bin/python auditoria-producao/run_homologation_offline.py
.venv-signer/bin/python auditoria-producao/run_homologation_offline.py --native
.venv-signer/bin/python -c 'from rh.native_secp import backend_info; print(backend_info())'
```

These commands use disposable fixtures or inspect the backend without loading
operator wallets. They do not transmit transactions.

To recreate the environment, use a trusted CPython 3.12 interpreter on this Mac:

```sh
/absolute/path/to/python3.12 -m venv .venv-signer
.venv-signer/bin/python -m pip --isolated install \
  --index-url https://pypi.org/simple --cert /etc/ssl/cert.pem \
  --require-hashes --only-binary=:all: --no-deps -r requirements-signer.lock
```

`requirements-signer.lock` pins the exact macOS arm64 CPython 3.12 wheel hash.
`rh/native_secp_distribution.json` pins its ten Python/native code-file hashes.
The backend checks the runtime, version and package files before its first
import, then initializes a randomized process-local native context. Failure or
an unsupported runtime blocks private operations; there is no Python fallback.

The ordinary `python3` currently selects Python 3.14.7 and was tested to fail
closed for signing. No published Python 3.14 wheel was present in Coincurve
21.0.0's official distribution list. Other operating systems, architectures or
Python ABIs need a separately verified distribution/profile; source builds or
unverified upgrades are not selected automatically.

For the actual RHEX CLI folder, use the root environment's interpreter while
working there, or recreate an equivalent environment from its copied lock:

```sh
../.venv-signer/bin/python -c 'from rh.native_secp import backend_info; print(backend_info())'
```

The upstream primitive is extensively reviewed and declares constant-time
secret operations. No independent external security-audit report covering
this exact wheel and local binding has been established. Native migration and
functional/provenance verification are distinguished from an external audit
certificate in the current report. Python input conversion, caller-held key
objects, custody AES, memory erasure and whole-host physical side-channel
assurance are outside the native primitive's guarantees.

See [the native signer evidence report](./auditoria-producao/NATIVE_SIGNER_REVALIDATION.md).

A separate AI source/binary review now covers the exact pinned artifacts and final binding. Four integration issues were corrected with independent rechecks; formal external audit remains unestablished. The bridge additionally checks selected source bytecode caches, loaded extension origins and semantic signature/public-point outputs. See [the exact-artifact review](./auditoria-producao/NATIVE_EXACT_ARTIFACT_REVIEW.md).

Custody AES additionally requires the pinned native Rust/OpenSSL dependency set. Install both `requirements-signer.lock` and `requirements-custody.lock`; follow [NATIVE_CUSTODY_SETUP.md](./NATIVE_CUSTODY_SETUP.md). The signer profile/binary are unchanged by this addition.
