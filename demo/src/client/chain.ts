import { ccc } from "@ckb-ccc/core";

import { bytesFromHex, hexFromBytes } from "../shared/bytes.js";
import {
  CLIENT_ORIGIN,
  EXPLORER_URL,
  FEE_RATE,
  OP_SPEND,
  SHANNONS_PER_CKB,
  TRANSFER_CAPACITY,
} from "../shared/constants.js";
import type { VerifiedAccount } from "../shared/manifests.js";
import {
  authorizationDigest as createAuthorizationDigest,
  ckbHash,
  encodeAccountWitness,
  encodeP256Proof,
  groupSighash,
  packAccountWitness,
} from "../shared/protocol.js";
import {
  CommittedReceiptSchema,
  ConfirmationTimedOutReceiptSchema,
  PasskeyRecordSchema,
  SubmittedReceiptSchema,
  type CommittedReceipt,
  type ConfirmationTimedOutReceipt,
  type PasskeyRecord,
  type SubmittedReceipt,
} from "../shared/schemas.js";
import type { AssertionMaterial } from "./passkey.js";

const MAX_AUTHENTICATOR_DATA_BYTES = 1024;
const MAX_CLIENT_DATA_BYTES = 2048;
const MAX_DER_SIGNATURE_BYTES = 72;
const MIN_AUTHENTICATOR_DATA_BYTES = 37;
const STATE_HEADER_BYTES = 32;
const STATE_ENTRY_BYTES_WITHOUT_VARIABLE_DATA = 48;
const STATE_MAGIC = "CKAS";
const EXPECTED_RP_ID_HASH =
  "49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d9763";
const EXPECTED_ORIGIN_HASH =
  "4e90ec8f9d9b8d5bd3877ac003797738ff48419fcf8f97821a875ea4671955b6";

export interface SpendClient {
  readonly addressPrefix: string;
  getCellLive(
    outPoint: ccc.OutPointLike,
    withData?: boolean | null,
    includeTxPool?: boolean | null,
  ): Promise<ccc.Cell | undefined>;
  findCellsByLock(
    lock: ccc.ScriptLike,
    type?: ccc.ScriptLike | null,
    withData?: boolean,
    order?: "asc" | "desc",
    limit?: number,
  ): AsyncGenerator<ccc.Cell>;
  sendTransaction(transaction: ccc.TransactionLike): Promise<`0x${string}`>;
  waitTransaction(
    txHash: ccc.HexLike,
    confirmations?: number,
    timeout?: number,
  ): Promise<unknown>;
}

export interface SpendReview {
  inputCapacityShannons: string;
  transferCapacityShannons: string;
  changeCapacityShannons: string;
  feeShannons: string;
  funderAddress: string;
  inputOutPoint: { txHash: string; index: number };
  dependencies: readonly {
    name: "account_lock" | "verifier_p256" | "account_state";
    txHash: string;
    index: number;
  }[];
}

export interface PrepareSpendInput {
  client: SpendClient;
  account: VerifiedAccount;
  funderAddress: string;
  passkey: PasskeyRecord;
}

export interface PreparedSpend {
  transaction: ccc.Transaction;
  authorizationDigest: Uint8Array;
  review: SpendReview;
  maxWitnessBytes: number;
  sequence: bigint;
  credentialId: string;
  publicKey: string;
  accountId: string;
  stateData: string;
}

interface ParsedState {
  sequence: bigint;
  keyId: Uint8Array;
}

function fail(message: string): never {
  throw new TypeError(message);
}

function sameOutPoint(cell: ccc.Cell, value: { tx_hash: string; index: number }): boolean {
  return cell.outPoint.eq({ txHash: value.tx_hash, index: value.index });
}

function parseAccountState(dataHex: string, account: VerifiedAccount): ParsedState {
  const data = bytesFromHex(dataHex);
  if (data.length !== account.manifest.state_bytes || data.length < STATE_HEADER_BYTES) {
    return fail("Live account state data length does not match the manifest");
  }
  if (new TextDecoder().decode(data.subarray(0, 4)) !== STATE_MAGIC || data[4] !== 1) {
    return fail("Live account state data has an unsupported header");
  }
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  if (
    data[5] !== 1 ||
    view.getUint16(6, true) !== STATE_HEADER_BYTES ||
    view.getUint16(16, true) !== 1 ||
    view.getUint16(18, true) !== 1 ||
    view.getUint16(20, true) !== 1 ||
    data[22] !== 1 ||
    data[23] !== 0 ||
    view.getBigUint64(24, true) !== 0n
  ) {
    return fail("Live account state data does not match the supported account profile");
  }

  const entryLength = view.getUint16(32, true);
  const keyIdLength = view.getUint16(76, true);
  const auxLength = view.getUint16(78, true);
  if (
    entryLength !== data.length - STATE_HEADER_BYTES ||
    entryLength !== STATE_ENTRY_BYTES_WITHOUT_VARIABLE_DATA + keyIdLength + auxLength ||
    view.getUint16(34, true) !== 0 ||
    view.getUint16(36, true) !== 1 ||
    view.getUint16(38, true) !== 7 ||
    view.getUint16(40, true) !== 1 ||
    data[42] !== 0 ||
    data[43] !== 1 ||
    keyIdLength !== 32 ||
    auxLength !== 65
  ) {
    return fail("Live account state authenticator is not the supported P-256 profile");
  }
  const verifierCodeHash = hexFromBytes(data.subarray(44, 76));
  if (verifierCodeHash !== account.deployment.verifierP256Code.codeHash) {
    return fail("Live account state verifier does not match the deployment");
  }
  const keyIdStart = 80;
  const auxStart = keyIdStart + keyIdLength;
  const expectedAux = `01${EXPECTED_RP_ID_HASH}${EXPECTED_ORIGIN_HASH}`;
  if (hexFromBytes(data.subarray(auxStart)).slice(2) !== expectedAux) {
    return fail("Live account state data has an unexpected WebAuthn binding");
  }
  return {
    sequence: view.getBigUint64(8, true),
    keyId: data.slice(keyIdStart, auxStart),
  };
}

function verifyStateCell(state: ccc.Cell, account: VerifiedAccount): ParsedState {
  if (!sameOutPoint(state, account.manifest.state_out_point)) {
    return fail("Live state outpoint does not match the account manifest");
  }
  if (!state.cellOutput.lock.eq(account.accountLock)) {
    return fail("Live state lock does not match AccountLock");
  }
  if (state.cellOutput.type === undefined || !state.cellOutput.type.eq(account.stateType)) {
    return fail("Live state Type ID script does not match the account");
  }
  return parseAccountState(state.outputData, account);
}

export async function discoverAccountCells(
  client: SpendClient,
  account: VerifiedAccount,
): Promise<{ state: ccc.Cell; asset: ccc.Cell }> {
  const state = await client.getCellLive(
    {
      txHash: account.manifest.state_out_point.tx_hash,
      index: account.manifest.state_out_point.index,
    },
    true,
    true,
  );
  if (state === undefined) {
    throw new TypeError("Account state cell is spent or unavailable");
  }
  verifyStateCell(state, account);

  const assets: ccc.Cell[] = [];
  for await (const cell of client.findCellsByLock(
    account.accountLock,
    undefined,
    true,
    "asc",
    3,
  )) {
    if (!cell.cellOutput.lock.eq(account.accountLock)) {
      throw new TypeError("Indexer returned a cell with a foreign lock");
    }
    if (sameOutPoint(cell, account.manifest.state_out_point)) {
      verifyStateCell(cell, account);
      continue;
    }
    if (cell.cellOutput.type !== undefined) {
      throw new TypeError("AccountLock scan returned a typed asset candidate");
    }
    if (cell.outputData !== "0x") {
      throw new TypeError("AccountLock asset candidate contains data");
    }
    assets.push(cell);
    if (assets.length > 1) break;
  }
  if (assets.length !== 1) {
    throw new TypeError("Expected exactly one AccountLock asset cell");
  }
  const asset = assets[0]!;
  if (!sameOutPoint(asset, account.manifest.asset_out_point)) {
    throw new TypeError("Live asset outpoint does not match the account manifest");
  }
  const liveAsset = await client.getCellLive(
    {
      txHash: account.manifest.asset_out_point.tx_hash,
      index: account.manifest.asset_out_point.index,
    },
    true,
    true,
  );
  if (
    liveAsset === undefined ||
    !sameOutPoint(liveAsset, account.manifest.asset_out_point) ||
    !liveAsset.cellOutput.lock.eq(account.accountLock) ||
    liveAsset.cellOutput.type !== undefined ||
    liveAsset.outputData !== "0x" ||
    liveAsset.cellOutput.capacity !== asset.cellOutput.capacity
  ) {
    throw new TypeError("AccountLock asset cell is spent or changed");
  }
  return { state, asset: liveAsset };
}

function maximumWitness(publicKey: Uint8Array, sequence: bigint): Uint8Array {
  const signature = new Uint8Array(MAX_DER_SIGNATURE_BYTES);
  signature[0] = 0x30;
  signature[1] = MAX_DER_SIGNATURE_BYTES - 2;
  const proof = encodeP256Proof({
    publicKey,
    origin: new TextEncoder().encode(CLIENT_ORIGIN),
    authenticatorData: new Uint8Array(MAX_AUTHENTICATOR_DATA_BYTES),
    clientDataJson: new Uint8Array(MAX_CLIENT_DATA_BYTES),
    signature,
  });
  return packAccountWitness(encodeAccountWitness(OP_SPEND, sequence, [{ slot: 0, bytes: proof }]));
}

function ensureOccupiedCapacity(output: ccc.CellOutput, label: string): void {
  const minimum = BigInt(output.occupiedSize) * SHANNONS_PER_CKB;
  if (output.capacity < minimum) {
    throw new RangeError(`${label} output is below occupied capacity`);
  }
}

export async function prepareSpend(input: PrepareSpendInput): Promise<PreparedSpend> {
  const passkey = PasskeyRecordSchema.parse(input.passkey);
  const publicKey = bytesFromHex(passkey.publicKey);
  if (hexFromBytes(ckbHash(publicKey)) !== passkey.keyId) {
    throw new TypeError("Stored passkey key ID does not match its public key");
  }
  const { state, asset } = await discoverAccountCells(input.client, input.account);
  const parsedState = parseAccountState(state.outputData, input.account);
  if (hexFromBytes(parsedState.keyId) !== passkey.keyId) {
    throw new TypeError("Passkey does not match the live account state");
  }
  const funderLock = (
    await ccc.Address.fromString(input.funderAddress, input.client as unknown as ccc.Client)
  ).script;
  const inputCapacity = asset.cellOutput.capacity;
  if (inputCapacity <= TRANSFER_CAPACITY) {
    throw new RangeError("AccountLock asset cannot cover the fixed transfer and fee");
  }

  const placeholder = maximumWitness(publicKey, parsedState.sequence);
  const transaction = ccc.Transaction.from({
    cellDeps: [
      input.account.deployment.accountLockDep,
      input.account.deployment.verifierP256Dep,
      input.account.stateDep,
    ],
    inputs: [{ previousOutput: asset.outPoint }],
    outputs: [
      { capacity: TRANSFER_CAPACITY, lock: funderLock },
      {
        capacity: inputCapacity - TRANSFER_CAPACITY,
        lock: input.account.accountLock,
      },
    ],
    outputsData: ["0x", "0x"],
    witnesses: [hexFromBytes(placeholder)],
  });
  const fee = transaction.estimateFee(FEE_RATE);
  const change = inputCapacity - TRANSFER_CAPACITY - fee;
  if (change <= 0n) {
    throw new RangeError("AccountLock asset cannot cover the fixed transfer and fee");
  }
  transaction.outputs[1]!.capacity = change;
  ensureOccupiedCapacity(transaction.outputs[0]!, "Transfer");
  ensureOccupiedCapacity(transaction.outputs[1]!, "Change");

  const txHash = ccc.bytesFrom(transaction.hash());
  const firstWitness = ccc.bytesFrom(transaction.witnesses[0]!);
  const canonicalGroupSighash = groupSighash(txHash, [firstWitness], []);
  const digest = createAuthorizationDigest({
    operation: OP_SPEND,
    accountId: bytesFromHex(input.account.manifest.account_id),
    sequence: parsedState.sequence,
    state: bytesFromHex(state.outputData),
    groupSighash: canonicalGroupSighash,
  });
  return {
    transaction,
    authorizationDigest: digest,
    review: {
      inputCapacityShannons: inputCapacity.toString(),
      transferCapacityShannons: TRANSFER_CAPACITY.toString(),
      changeCapacityShannons: change.toString(),
      feeShannons: fee.toString(),
      funderAddress: input.funderAddress,
      inputOutPoint: {
        txHash: asset.outPoint.txHash,
        index: Number(asset.outPoint.index),
      },
      dependencies: [
        {
          name: "account_lock",
          txHash: input.account.deployment.accountLockDep.outPoint.txHash,
          index: Number(input.account.deployment.accountLockDep.outPoint.index),
        },
        {
          name: "verifier_p256",
          txHash: input.account.deployment.verifierP256Dep.outPoint.txHash,
          index: Number(input.account.deployment.verifierP256Dep.outPoint.index),
        },
        {
          name: "account_state",
          txHash: input.account.stateDep.outPoint.txHash,
          index: Number(input.account.stateDep.outPoint.index),
        },
      ],
    },
    maxWitnessBytes: placeholder.length,
    sequence: parsedState.sequence,
    credentialId: passkey.credentialId,
    publicKey: passkey.publicKey,
    accountId: input.account.manifest.account_id,
    stateData: state.outputData,
  };
}

function base64url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

function validateClientData(prepared: PreparedSpend, bytes: Uint8Array): void {
  let value: unknown;
  try {
    value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    return fail("Assertion client data is not valid UTF-8 JSON");
  }
  if (typeof value !== "object" || value === null) {
    return fail("Assertion client data is malformed");
  }
  const fields = value as Record<string, unknown>;
  if (
    fields.type !== "webauthn.get" ||
    fields.challenge !== base64url(prepared.authorizationDigest) ||
    fields.origin !== CLIENT_ORIGIN ||
    (fields.crossOrigin !== undefined && fields.crossOrigin !== false)
  ) {
    return fail("Assertion client data does not authorize this transaction");
  }
}

function validateDerSignature(signature: Uint8Array): void {
  if (
    signature.length < 8 ||
    signature.length > MAX_DER_SIGNATURE_BYTES ||
    signature[0] !== 0x30 ||
    signature[1] !== signature.length - 2
  ) {
    throw new TypeError("Assertion signature is not bounded P-256 DER");
  }
}

export function finalizeSpend(
  prepared: PreparedSpend,
  passkeyValue: PasskeyRecord,
  assertion: AssertionMaterial,
): ccc.Transaction {
  const passkey = PasskeyRecordSchema.parse(passkeyValue);
  if (
    assertion.credentialId !== prepared.credentialId ||
    passkey.credentialId !== prepared.credentialId ||
    passkey.publicKey !== prepared.publicKey
  ) {
    throw new TypeError("Assertion credential does not match the prepared spend");
  }
  if (
    assertion.authenticatorData.length < MIN_AUTHENTICATOR_DATA_BYTES ||
    assertion.authenticatorData.length > MAX_AUTHENTICATOR_DATA_BYTES
  ) {
    throw new RangeError("Assertion authenticator data is outside supported bounds");
  }
  if (
    assertion.clientDataJson.length === 0 ||
    assertion.clientDataJson.length > MAX_CLIENT_DATA_BYTES
  ) {
    throw new RangeError("Assertion client data is outside supported bounds");
  }
  validateDerSignature(assertion.signature);
  validateClientData(prepared, assertion.clientDataJson);

  const proof = encodeP256Proof({
    publicKey: bytesFromHex(passkey.publicKey),
    origin: new TextEncoder().encode(CLIENT_ORIGIN),
    authenticatorData: assertion.authenticatorData,
    clientDataJson: assertion.clientDataJson,
    signature: assertion.signature,
  });
  const witness = packAccountWitness(
    encodeAccountWitness(OP_SPEND, prepared.sequence, [{ slot: 0, bytes: proof }]),
  );
  if (witness.length > prepared.maxWitnessBytes) {
    throw new RangeError("Assertion witness exceeds the prepared fee reservation");
  }
  const finalized = prepared.transaction.clone();
  finalized.witnesses[0] = hexFromBytes(witness);
  if (finalized.hash() !== prepared.transaction.hash()) {
    throw new TypeError("Finalizing the witness changed raw transaction fields");
  }
  return finalized;
}

export async function submitSpend(
  client: SpendClient,
  transaction: ccc.Transaction,
): Promise<SubmittedReceipt> {
  if (transaction.outputs.length !== 2 || transaction.outputsData.length !== 2) {
    throw new TypeError("Spend transaction has an unexpected output shape");
  }
  const txHash = await client.sendTransaction(transaction);
  return SubmittedReceiptSchema.parse({
    status: "submitted",
    txHash,
    explorerUrl: `${EXPLORER_URL}${txHash}`,
    remainingCapacityShannons: transaction.outputs[1]!.capacity.toString(),
  });
}

function isConfirmationTimeout(error: unknown): boolean {
  return error instanceof ccc.ErrorClientWaitTransactionTimeout ||
    (error instanceof Error && error.name === "ErrorClientWaitTransactionTimeout");
}

export async function confirmSpend(
  client: SpendClient,
  submittedValue: SubmittedReceipt,
): Promise<CommittedReceipt | ConfirmationTimedOutReceipt> {
  const submitted = SubmittedReceiptSchema.parse(submittedValue);
  try {
    const response = await client.waitTransaction(submitted.txHash, 0, 300_000);
    if (response === undefined) {
      throw new TypeError("Committed transaction response is unavailable");
    }
  } catch (error) {
    if (!isConfirmationTimeout(error)) throw error;
    return ConfirmationTimedOutReceiptSchema.parse({
      ...submitted,
      status: "confirmation_timeout",
    });
  }
  const change = await client.getCellLive(
    { txHash: submitted.txHash, index: 1 },
    true,
    true,
  );
  if (
    change === undefined ||
    change.cellOutput.type !== undefined ||
    change.outputData !== "0x" ||
    change.cellOutput.capacity.toString() !== submitted.remainingCapacityShannons
  ) {
    throw new TypeError("Committed AccountLock change could not be verified");
  }
  return CommittedReceiptSchema.parse({ ...submitted, status: "committed" });
}
