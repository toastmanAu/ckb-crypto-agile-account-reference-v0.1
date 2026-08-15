import { ccc } from "@ckb-ccc/core";

/**
 * CKB's built-in Type ID code hash: ASCII `TYPE_ID`, left-padded to 32 bytes.
 * Type ID is implemented by consensus, so the script needs no cell dep.
 */
export const TYPE_ID_CODE_HASH =
  "0x00000000000000000000000000000000000000000000000000545950455f4944";

/** AccountLockV1 args version byte. */
export const ACCOUNT_LOCK_VERSION = 0x01;

/** Builds the singleton Account State Type ID script. */
export function typeIdScript(typeIdArgs: string): ccc.Script {
  return ccc.Script.from({
    codeHash: TYPE_ID_CODE_HASH,
    hashType: "type",
    args: typeIdArgs,
  });
}

/**
 * The account's identity: the script hash of its Type ID script.
 *
 * Cross-checked against `crates/host/tests/identity.rs`.
 */
export function accountIdFromTypeIdArgs(typeIdArgs: string): string {
  return typeIdScript(typeIdArgs).hash();
}

/** AccountLock args, which are exactly `0x01 || account_id`. */
export function accountLockArgs(accountId: string): string {
  const id = ccc.bytesFrom(accountId);
  if (id.length !== 32) {
    throw new Error(`account id must be 32 bytes, got ${id.length}`);
  }
  const args = new Uint8Array(33);
  args[0] = ACCOUNT_LOCK_VERSION;
  args.set(id, 1);
  return ccc.hexFrom(args);
}

/**
 * The AccountLock script for an account.
 *
 * These ELFs are published as plain data cells, so the lock is addressed by
 * data hash with the CKB2023-compatible `data2` hash type.
 */
export function accountLockScript(
  accountLockCodeHash: string,
  accountId: string,
): ccc.Script {
  return ccc.Script.from({
    codeHash: accountLockCodeHash,
    hashType: "data2",
    args: accountLockArgs(accountId),
  });
}

function sameHex(left: string, right: string): boolean {
  return left.toLowerCase() === right.toLowerCase();
}

/**
 * Verifies a creation transaction before it is broadcast.
 *
 * The consensus TYPE_ID script validates the state cell's own args when the
 * cell is created, but *nothing on chain* validates that the AccountLock args
 * commit to that Type ID script. A lock script runs only when its cell is
 * consumed, so wrong args produce cells that broadcast cleanly, look correct in
 * any explorer, and can never be unlocked. This check is the only thing
 * standing between a typo and permanently frozen capacity.
 */
export function assertCreationConsistency(
  tx: ccc.Transaction,
  accountLockCodeHash: string,
  expectedStateData: string,
): void {
  if (tx.inputs.length === 0) {
    throw new Error("creation transaction has no inputs");
  }
  // completeFeeBy appends a change output, so a real creation transaction has
  // three outputs. Outputs beyond the first two must not belong to the account.
  if (tx.outputs.length < 2) {
    throw new Error(
      `creation transaction must have at least 2 outputs (state, asset), got ${tx.outputs.length}`,
    );
  }

  const stateOutput = tx.outputs[0];
  if (!stateOutput.type) {
    throw new Error("output 0 has no type script; the state cell needs a Type ID");
  }

  const expectedTypeIdArgs = ccc.hashTypeId(tx.inputs[0], 0);
  if (!sameHex(stateOutput.type.args, expectedTypeIdArgs)) {
    throw new Error(
      `output 0 type id args ${stateOutput.type.args} do not match ` +
        `hashTypeId(inputs[0], 0) = ${expectedTypeIdArgs}`,
    );
  }
  if (!sameHex(stateOutput.type.codeHash, TYPE_ID_CODE_HASH)) {
    throw new Error(`output 0 type code hash is not the consensus TYPE_ID script`);
  }

  const accountId = stateOutput.type.hash();
  const expectedArgs = accountLockArgs(accountId);

  for (const [index, output] of tx.outputs.slice(2).entries()) {
    if (sameHex(output.lock.codeHash, accountLockCodeHash)) {
      throw new Error(
        `unexpected AccountLock output at index ${index + 2}; only the state and ` +
          `asset cells may belong to the account, and change must return to the deployer`,
      );
    }
  }

  for (const [index, output] of tx.outputs.slice(0, 2).entries()) {
    if (!sameHex(output.lock.codeHash, accountLockCodeHash)) {
      throw new Error(
        `output ${index} lock code hash ${output.lock.codeHash} is not AccountLock ` +
          `(${accountLockCodeHash})`,
      );
    }
    if (output.lock.hashType !== "data2") {
      throw new Error(
        `output ${index} lock hash type must be data2, got ${output.lock.hashType}`,
      );
    }
    if (!sameHex(output.lock.args, expectedArgs)) {
      throw new Error(
        `output ${index} lock args ${output.lock.args} do not commit to this ` +
          `transaction's account id ${accountId}; expected ${expectedArgs}. ` +
          `Broadcasting would create permanently unspendable cells.`,
      );
    }
  }

  if (!sameHex(tx.outputsData[0] ?? "0x", expectedStateData)) {
    throw new Error(
      `output 0 state data does not match the encoded AccountStateV1 bytes`,
    );
  }
}
