import { describe, expect, it } from "vitest";
import { ccc } from "@ckb-ccc/core";

import {
  ACCOUNT_LOCK_VERSION,
  TYPE_ID_CODE_HASH,
  accountIdFromTypeIdArgs,
  accountLockArgs,
  accountLockScript,
  assertCreationConsistency,
  typeIdScript,
} from "../src/account.js";

/**
 * Cross-language oracle. `crates/host/tests/identity.rs` pins these same bytes
 * from ckb-types, the implementation consensus itself uses, and they were
 * independently reproduced from a hand-rolled Script molecule in Python.
 *
 * The AccountLock args are never executed when the account is created — a lock
 * script runs only when its cell is consumed — so a divergence here would not
 * surface until the first spend, by which point the cells hold value and are
 * unspendable forever.
 */
const TYPE_ID_ARGS = `0x${"11".repeat(32)}`;
const GOLDEN_ACCOUNT_ID =
  "0x5e6ca9ef85719d5b2bd485a254ffedfff44c1ee1f386e42aecf6823ec9fc5bf7";
const GOLDEN_LOCK_ARGS =
  "0x015e6ca9ef85719d5b2bd485a254ffedfff44c1ee1f386e42aecf6823ec9fc5bf7";

const ACCOUNT_LOCK_CODE_HASH =
  "0xc546913fec9a02ebdf59c7e22e38bd5d9bb07bea81985c4cf8288040f0480abe";

describe("type id script", () => {
  it("uses the consensus TYPE_ID code hash with the type hash type", () => {
    expect(TYPE_ID_CODE_HASH).toBe(
      "0x00000000000000000000000000000000000000000000000000545950455f4944",
    );

    const script = typeIdScript(TYPE_ID_ARGS);
    expect(script.codeHash).toBe(TYPE_ID_CODE_HASH);
    expect(script.hashType).toBe("type");
    expect(script.args).toBe(TYPE_ID_ARGS);
  });
});

describe("account identity", () => {
  it("derives the same account_id as the Rust reference implementation", () => {
    expect(accountIdFromTypeIdArgs(TYPE_ID_ARGS)).toBe(GOLDEN_ACCOUNT_ID);
  });

  it("builds lock args as the version byte followed by the account id", () => {
    const args = accountLockArgs(GOLDEN_ACCOUNT_ID);

    expect(args).toBe(GOLDEN_LOCK_ARGS);
    expect(ccc.bytesFrom(args).length).toBe(33);
    expect(ccc.bytesFrom(args)[0]).toBe(ACCOUNT_LOCK_VERSION);
  });

  it("addresses AccountLock by data hash using data2", () => {
    const lock = accountLockScript(ACCOUNT_LOCK_CODE_HASH, GOLDEN_ACCOUNT_ID);

    expect(lock.codeHash).toBe(ACCOUNT_LOCK_CODE_HASH);
    expect(lock.hashType).toBe("data2");
    expect(lock.args).toBe(GOLDEN_LOCK_ARGS);
  });
});

function creationTransaction(overrides: {
  stateArgs?: string;
  stateLockArgs?: string;
  assetLockArgs?: string;
} = {}) {
  const input = ccc.CellInput.from({
    previousOutput: { txHash: `0x${"aa".repeat(32)}`, index: 0 },
    since: 0,
  });
  const typeIdArgs = ccc.hashTypeId(input, 0);
  const accountId = accountIdFromTypeIdArgs(overrides.stateArgs ?? typeIdArgs);
  const lockArgs = accountLockArgs(accountId);

  return {
    input,
    typeIdArgs,
    tx: ccc.Transaction.from({
      inputs: [input],
      outputs: [
        {
          lock: {
            codeHash: ACCOUNT_LOCK_CODE_HASH,
            hashType: "data2",
            args: overrides.stateLockArgs ?? lockArgs,
          },
          type: typeIdScript(overrides.stateArgs ?? typeIdArgs),
        },
        {
          lock: {
            codeHash: ACCOUNT_LOCK_CODE_HASH,
            hashType: "data2",
            args: overrides.assetLockArgs ?? lockArgs,
          },
        },
      ],
      outputsData: ["0xdeadbeef", "0x"],
    }),
  };
}

describe("assertCreationConsistency", () => {
  it("accepts a correctly derived creation transaction", () => {
    const { tx } = creationTransaction();
    expect(() =>
      assertCreationConsistency(tx, ACCOUNT_LOCK_CODE_HASH, "0xdeadbeef"),
    ).not.toThrow();
  });

  it("rejects a state cell whose Type ID args do not match the first input", () => {
    // The consensus TYPE_ID script would also reject this, but failing here
    // avoids burning a transaction to learn it.
    const { tx } = creationTransaction({ stateArgs: `0x${"22".repeat(32)}` });
    expect(() =>
      assertCreationConsistency(tx, ACCOUNT_LOCK_CODE_HASH, "0xdeadbeef"),
    ).toThrow(/type id args/i);
  });

  it("rejects lock args that do not commit to the state cell's own type script", () => {
    // This is the permanent-brick case: the Type ID script validates on
    // creation, but nothing validates that the lock args name it.
    const { tx } = creationTransaction({
      stateLockArgs: accountLockArgs(`0x${"33".repeat(32)}`),
    });
    expect(() =>
      assertCreationConsistency(tx, ACCOUNT_LOCK_CODE_HASH, "0xdeadbeef"),
    ).toThrow(/account id/i);
  });

  it("rejects an asset cell locked to a different account", () => {
    const { tx } = creationTransaction({
      assetLockArgs: accountLockArgs(`0x${"44".repeat(32)}`),
    });
    expect(() =>
      assertCreationConsistency(tx, ACCOUNT_LOCK_CODE_HASH, "0xdeadbeef"),
    ).toThrow(/output 1/i);
  });

  it("rejects state cell data that is not the encoded state", () => {
    const { tx } = creationTransaction();
    expect(() =>
      assertCreationConsistency(tx, ACCOUNT_LOCK_CODE_HASH, "0xc0ffee"),
    ).toThrow(/state data/i);
  });
});

describe("assertCreationConsistency with fee change", () => {
  // completeFeeBy appends a change output, so a real creation transaction has
  // three outputs, not two.
  function withChangeOutput(changeLockCodeHash: string, changeArgs: string) {
    const { tx } = creationTransaction();
    tx.outputs.push(
      ccc.CellOutput.from({
        lock: { codeHash: changeLockCodeHash, hashType: "type", args: changeArgs },
        capacity: 0,
      }),
    );
    tx.outputsData.push("0x");
    return tx;
  }

  it("accepts a trailing change output locked by the deployer", () => {
    const tx = withChangeOutput(`0x${"9c".repeat(32)}`, `0x${"ab".repeat(20)}`);
    expect(() =>
      assertCreationConsistency(tx, ACCOUNT_LOCK_CODE_HASH, "0xdeadbeef"),
    ).not.toThrow();
  });

  it("rejects a further output locked by AccountLock", () => {
    // An extra account-locked output is capacity assigned to the account that
    // the operator did not plan for and cannot see in the plan output.
    const tx = withChangeOutput(ACCOUNT_LOCK_CODE_HASH, `0x${"ab".repeat(33)}`);
    expect(() =>
      assertCreationConsistency(tx, ACCOUNT_LOCK_CODE_HASH, "0xdeadbeef"),
    ).toThrow(/unexpected AccountLock output/i);
  });

  it("rejects a transaction with fewer than two outputs", () => {
    const { tx } = creationTransaction();
    tx.outputs.pop();
    tx.outputsData.pop();
    expect(() =>
      assertCreationConsistency(tx, ACCOUNT_LOCK_CODE_HASH, "0xdeadbeef"),
    ).toThrow(/at least 2 outputs/i);
  });
});
