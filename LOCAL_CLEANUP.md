# Local source-only copy

Prepared locally on 2026-10-15. Nothing was uploaded, no GitHub repository was
created, and no local Git history is included. This directory is the cleaned
copy; the original working directory still contains its private operator data.
Do not share or stage the parent directory.

The copy was assembled from an explicit source-file list. It excludes actual
wallets, encrypted keystores/backups, operator configuration and plans, nonces,
locks, environment files, venvs, caches, wheels, archives, raw audit reports,
mail receipts and historical transcripts. Personal home/project paths and
personal email/name occurrences were removed from the selected text files.
Protocol contract addresses and public cryptographic test vectors are not
operator private data. Test scalars and synthetic passwords are public fixtures
and must never be used to hold funds.

No operator wallet/key content was opened, copied, hashed or deleted. Originals
were preserved to avoid losing access to funds. No secret was rotated: no live
credential was read to establish whether prior exposure occurred. This work is
local privacy hygiene, not production acceptance or cryptographic certification.

The two dependency hash locks and native profiles remain included. Actual
dependency binaries/venvs are excluded. Recreate the pinned runtime separately
if needed, using the setup instructions; it is limited to the documented Mac
arm64 / CPython 3.12 environment. References in historical documentation to
excluded audit reports are not evidence bundled with this copy.

The included native/custody regression runner uses only public disposable
fixtures, blocks network and copies no operator-data directory. From this
directory, an already trusted compatible interpreter can run:

```sh
../.venv-signer/bin/python auditoria-producao/run_native_audit_package.py
gitleaks dir . --config .gitleaks.toml --ignore-gitleaks-allow --redact=100
```

Do not run wallet-generation or trading commands as part of privacy validation.
The local-only cleanup does not change the campaign planner/executor behavior.
The original full application gate/evidence archive is not copied. Only the six
focused native/custody suites are included here. No publication is authorized
by this local-only step.

## Validation of this local checkpoint

The privacy scan passed for 29 selected/generated text files. The requested
personal terms have zero case-insensitive occurrences in this copy. Gitleaks
8.30.1 reports zero unreviewed findings with four exact reviewed public hashes
allowed; no test directory or secret-detection rule was disabled. Six synthetic
negative controls reject a private-key literal, mixed-case personal term, home
path, email, credential-bearing URL and runtime wallet artifact. The six focused
native/custody suites passed all 78 tests using the existing pinned runtime.
The source crypto bridges, package profiles and dependency hash locks remain
byte-identical to the originals. No production readiness claim follows.
