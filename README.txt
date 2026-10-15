NATIVE CUSTODY AES UPDATE (2026-10-13): Encryption/decryption require the verified Cryptography/Rust-OpenSSL backend in .venv-signer, installed with requirements-custody.lock in addition to requirements-signer.lock. No Python AES fallback. See NATIVE_CUSTODY_SETUP.md and the AES evidence report. Earlier stdlib-only statements are historical.

NATIVE SIGNER UPDATE (2026-10-13): Private signing and public-key derivation require the verified Coincurve/libsecp256k1 environment. Use .venv-signer/bin/python from the root workspace (../.venv-signer/bin/python inside RHEX). There is no Python fallback. See NATIVE_SIGNER_SETUP.md and auditoria-producao/NATIVE_SIGNER_REVALIDATION.md. Historical stdlib-only runtime statements below are superseded for private operations.

ROBINHIDDEN v3.1  -  invisible bundling campaign builder for Pons V2 on Robinhood Chain
================================================================================================
Chain : Robinhood Chain (RHC), Arbitrum Orbit L2, chain ID 4663
RPC   : https://rpc.mainnet.chain.robinhood.com
Explorer: https://robinhoodchain.blockscout.com

WHAT IS INCLUDED (status as of 2026-10-10, validated through execution)
- Deterministic cohort engine (N EOAs) + 9 hygiene invariants compiled into assertions
  (intra-cohort edges=0, no deployer supply, hub degree>=500 with share<=3%, one provenance
  origin, timestamp CV>=0.6, amount CV>=0.75 with no twins within <2% and a 5% hold cap,
  no sweep to a shared destination, venue diversity, at most 1 cohort transaction/block).
- Realistic target: 55-65% of supply across 25+ wallets (cost ~E*f/(1-f); 90% would cost ~9x TVC).
- ABIs VERIFIED ON-CHAIN at block 85271310 (local keccak vs PUSH4 in live bytecode):
  router.launchAndBuy 0xf85f8e41 | curve buy 0x59a87bc1 / sell 0xd04c6983 + 12 views |
  factory 10 views | TokenLaunched topic0 0x8d4aad49... == real log. Source: pons v2 ABIs
  (Blockscout/ponsdotdev) through bodkin src/abi/pons.ts. Pre-graduation purchases run on the
  token CURVE (TokenLaunched topics[2]), not the router.
- Selftest suite: 72 offline tests + 9 live = 81/81 with network access (including pin drift checks).
- Confirmed live factory values: launch fee 0.0005 ETH, snipe tax 9900 bps decaying over 3s,
  maximum creator tax 1000 bps, per-wallet caps of 5% holdings / 5.5% purchase (enforced by the curve).

COMMANDS (python3, standard library only)
- main.py selftest
- main.py status
- main.py gen
- main.py plan
- main.py verify
- main.py doctor
- main.py run
- main.py sync

TYPICAL USAGE
  python3 main.py gen                       # generate wallets (data/wallets.json)
  python3 main.py plan --preset standard    # cohort of 25 EOAs: slots, caps, amounts
  python3 main.py verify <run_dir>          # check the 9 plan invariants
  python3 main.py doctor --plan <run_dir>   # check RPC, curve, snipe tax, and each wallet balance
  python3 main.py run --plan <run_dir> --token <addr>          # dry-run: construct and sign local transactions
  python3 main.py run --plan <run_dir> --token <addr> --send   # production: sign and broadcast transactions
  python3 main.py sync                      # list selectors that are still unnamed (audit)
  python3 selftest.py [--live]              # full suite (79 offline + 9 live)

OPEN ITEMS (explicitly unresolved, without promises)
- 'run' exists and has been validated through signed raw transaction creation (passing suite +
  live dry-run on 2026-10-11, recovered signer == from): dry-run by default; --send signs and
  broadcasts in parallel according to plan slots and waits for receipts. No real transaction has
  been executed: the wallets still have no ETH.
- Wallet addresses validated against classic curve vectors (priv=1 and priv=2 match the standard).
- Live funding graphs (Blockscout returns 403 from this IP): invariant I1 validates against
  an operator-supplied graph; automated collection is still manual.
- Planner robustness beyond seed 1337 and the standard preset has not been covered by an expanded suite.
- Leaks that cannot be solved by construction: the funding operator (exchange/paymaster/bridge)
  sees IP + timing; Robinhood sees everything off-chain; holder lists and Time Travel show
  concentration regardless of edges. The 55-65% range is the practical ceiling for invisibility.
