# Local CKB passkey demo

This local-only web demo creates a WebAuthn P-256 passkey, bootstraps a
passkey-controlled account against the repository's published CKB testnet code
cells, and authorizes one fixed 100 CKB spend. It is an unaudited reference
flow. It is not a wallet and must not be used with mainnet keys or funds.

The browser receives public deployment, account, cell, and receipt data only.
The CKB private key stays in the localhost Node process and funds account
creation; the passkey assertion authorizes the AccountLock spend in Chromium.

## Prerequisites

- Node.js 22 and npm
- the repository's pinned Rust toolchain, because account-state export invokes
  the host reference implementation
- Chromium installed for the browser tests (`npx playwright install chromium`)
- a CKB **testnet-only** private key whose address has at least 517 CKB plus
  ordinary transaction fees
- ports `127.0.0.1:5173` and `127.0.0.1:8787` available
- a Chromium profile whose platform authenticator/passkey support is enabled

The bootstrap plan for the deterministic 177-byte AccountState is:

| Output/reserve | Capacity |
|---|---:|
| Type ID AccountState cell | 316 CKB |
| AccountLock asset cell | 200 CKB |
| Local service fee reserve | 1 CKB |
| Minimum balance checked before bootstrap | 517 CKB |

The service verifies the immutable `data2` code cells recorded in
[`deploy/testnet-deployments.json`](../deploy/testnet-deployments.json) before
showing an actionable flow.

## Install and start safely

Install dependencies once:

```sh
npm --prefix tools/deploy install
npm --prefix demo install
```

Enter the key through a silent shell prompt so it is not written into shell
history or passed as a command argument:

```sh
cd demo
read -rsp "CKB testnet private key (0x…): " CKB_PRIVKEY
echo
export CKB_PRIVKEY
npm run dev
# After stopping the demo:
unset CKB_PRIVKEY
```

Open `http://localhost:5173` in Chromium. `npm run dev` starts the API on
`127.0.0.1:8787` and Vite on `127.0.0.1:5173`. Stop both with `Ctrl-C`, then run
`unset CKB_PRIVKEY` in the same shell even if startup or the browser flow
failed. Closing the browser does not remove an exported shell variable.

Never paste a private key into chat, a command argument, an `.env` file,
browser storage, screenshots, logs, issue reports, or a committed file. Never
use a mainnet key. The key is intentionally required only by server modules;
the production client bundle gate rejects server/key code.

## The three stages

1. **Create your passkey.** Chromium performs a WebAuthn registration for
   `localhost`. The browser stores only the credential ID, P-256 public key,
   key ID, and RP ID. Keep using this browser profile: deleting its passkey or
   site data can make the demo asset unspendable.
2. **Create your testnet account.** Review the public funder address, balance,
   two deployment hashes, passkey public material, and 200 CKB asset before
   clicking. The localhost service creates one Type ID AccountState cell and
   one AccountLock asset, waits for commitment, then atomically records the
   public manifest at `deploy/testnet-account.json`.
3. **Authorize your first spend.** Review the exact input, fixed 100 CKB
   transfer, change, fee, digest, and three cell deps. Chromium obtains a
   passkey assertion over that digest. The browser submits once, preserves the
   transaction hash immediately, waits for commitment, and rescans the live
   AccountLock change.

Cancellation before a passkey ceremony finishes is safe and retryable. After a
transaction hash appears, use **Check again** after a timeout; do not click
through a new send flow or create another transaction for the same intent.

## Explorer verification

All links must stay under `https://pudge.explorer.nervos.org/transaction/`.
Before trusting a result:

- compare the account creation hash with `state_out_point.tx_hash` and
  `asset_out_point.tx_hash` in `deploy/testnet-account.json`;
- confirm output index 0 is the Type ID AccountState and output index 1 is the
  200 CKB AccountLock asset;
- compare the AccountLock code hash with
  `0xc546913fec9a02ebdf59c7e22e38bd5d9bb07bea81985c4cf8288040f0480abe`;
- compare the P-256 verifier dep with
  `0x376a3e1bfefc57d63cff2e5d022283800fb6b5f014b5edac4be573d58a7b124a`;
- after spending, confirm the displayed transaction is committed and its
  change output remains a live cell under the same AccountLock.

Keep every displayed transaction hash when diagnosing a timeout or partial
failure. Hashes and addresses are public and safe to compare; private keys and
passkey assertions are not.

## Mismatch and interrupted-flow recovery

The service deliberately refuses to replace `deploy/testnet-account.json` and
the UI blocks when that manifest, on-chain state, and the browser passkey do not
agree. This prevents a retry from silently stranding capacity.

1. Stop `npm run dev`; do not delete or edit the manifest and do not attempt a
   second bootstrap.
2. Preserve the public manifest and every known transaction hash. Inspect the
   account and spend transactions in the testnet explorer.
3. Restart with the original Chromium profile and its original passkey. A new
   virtual/profile passkey will not match an existing account.
4. If a spend hash exists, return to its receipt and use **Check again**. This
   checks commitment and the expected live change without resubmitting.
5. If the manifest is absent after an account-creation interruption, reconcile
   the funder's on-chain outputs before taking any further action. Do not invent
   an outpoint or rerun bootstrap merely because the file is absent.

If the original passkey is lost, stop. The demo account has no alternate
recovery credential. Treat its AccountLock capacity as inaccessible and do not
try to bind a replacement credential to the existing manifest.

## Verification commands

The default demo gate is deterministic and does **not** read `CKB_PRIVKEY`, use
live CKB RPC fallbacks, or broadcast:

```sh
npm run check
```

It runs TypeScript checking, unit/integration tests, deterministic Chromium
tests, a production build, and the content + Vite/Rollup module-graph boundary
scan. Repository-level verification additionally uses:

```sh
cargo test -p ckb-account-host
npm --prefix tools/deploy test
npm --prefix tools/deploy run typecheck
./scripts/check.sh
git diff --check
```

`npm run test:testnet` is the only automated real-chain browser entry. The spec
is serial and skipped unless both the opt-in and valid hidden-prompt key are
present. It prints the capacity plan before bootstrap and retains discovered
public hashes on failure. Review the plan and ensure no account manifest/passkey
conflict exists before opting in:

```sh
export RUN_CKB_TESTNET=1
npm run test:testnet
unset RUN_CKB_TESTNET
unset CKB_PRIVKEY
```

Do not set `RUN_CKB_TESTNET=1` during routine verification or CI. The normal
`npm run check` gate runs only the deterministic public-data fixture.
