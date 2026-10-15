# Verified native custody AES environment

Date: 2026-10-13. Target: macOS arm64, CPython 3.12.14.

Custody AES now requires Cryptography 50.0.2 / native Rust-OpenSSL 4.0.3,
CFFI 2.1.1 and pycparser 3.11, in the existing project-only `.venv-signer`.
The handwritten Python AES implementation has been removed from runtime source.
Encryption and decryption have no Python AES fallback. The signing dependency
remains the separately pinned Coincurve 21.0.0.

Recreate with a trusted CPython 3.12 interpreter on a compatible Mac:

```sh
/absolute/path/to/python3.12 -m venv .venv-signer
.venv-signer/bin/python -m pip --isolated install \
  --index-url https://pypi.org/simple --cert /etc/ssl/cert.pem \
  --require-hashes --only-binary=:all: --no-deps \
  -r requirements-signer.lock -r requirements-custody.lock
```

For an offline recreation, use the archived wheels in both native evidence
directories with `--no-index --find-links`, retaining both locks and hash checks.
Do not substitute source builds, another ABI or an unreviewed dependency upgrade.
The AES profile pins 107 package Python/native code files; its selected bytecode
caches and loaded module origins are also checked. The bridge requires the
native cipher context type and a startup known-answer check. These protections
assume trusted local application/profile/interpreter files and do not attest
arbitrarily compromised process memory.

Safe reproduction from the repository root:

```sh
.venv-signer/bin/python audit/run_native_audit_package.py
.venv-signer/bin/python -m unittest audit/test_native_aes.py
.venv-signer/bin/python -m unittest audit/test_native_aes_security.py
.venv-signer/bin/python -c 'from rh.native_aes import backend_info; print(backend_info())'
```

These commands use public disposable fixtures or inspect the backend. They do
not load operator wallets, require your password, sign real transactions or
broadcast. Existing keystore formats/KDFs/MAC variants remain compatible; no
operator file has been migrated or rewritten. Native decryption runs only after
the existing keystore metadata/KDF bounds and MAC validation pass.

Inside RHEX, use `../.venv-signer/bin/python` or recreate an equivalent isolated
environment with both copied locks. The venv itself is not distributed as part
of the RHEX source mirror. System `python3` 3.14 is deliberately unsupported
by this validated runtime profile; do not use it for custody recovery.

The independent PyCryptodome comparison oracle is a test-only dependency under
`/private/tmp/rh-phase2-independent-crypto`; it is not a production fallback.

**Audit boundary:** OpenSSL has published upstream assessments, but those do not
certify this OpenSSL 4.0.3 AES-CTR image. Cryptography 50.0.2's documentation
states its code/documentation have not received an external audit. This setup
is a tested native migration, not an exact-build/binding audit or FIPS claim.
