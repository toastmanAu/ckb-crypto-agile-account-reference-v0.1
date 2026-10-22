import { WitnessArgs, bytesFrom, hashCkb, hexFrom } from "@ckb-ccc/core";

import {
  bytesConcat,
  hexFromBytes,
  u16le,
  u32le,
  u64le,
} from "./bytes.js";

const ACCOUNT_WITNESS_MAGIC = Uint8Array.of(0x43, 0x4b, 0x41, 0x57);
const ACCOUNT_WITNESS_VERSION = 1;
const ACCOUNT_WITNESS_MAX_LOCK_LEN = 131_072;
const AUTHENTICATOR_MAX_COUNT = 16;
const AUTH_DOMAIN = new TextEncoder().encode("CKB_ACCOUNT_LOCK_V1");

export interface P256ProofInput {
  publicKey: Uint8Array;
  origin: Uint8Array;
  authenticatorData: Uint8Array;
  clientDataJson: Uint8Array;
  signature: Uint8Array;
}

export interface Proof {
  slot: number;
  bytes: Uint8Array;
}

export interface AuthorizationInput {
  operation: 1 | 2 | 3;
  accountId: Uint8Array;
  sequence: bigint;
  state: Uint8Array;
  groupSighash: Uint8Array;
}

function requireOperation(operation: number): asserts operation is 1 | 2 | 3 {
  if (operation !== 1 && operation !== 2 && operation !== 3) {
    throw new RangeError("operation");
  }
}

function requireLength(bytes: Uint8Array, length: number, label: string): void {
  if (bytes.length !== length) {
    throw new RangeError(label);
  }
}

export function ckbHash(data: Uint8Array): Uint8Array {
  return bytesFrom(hashCkb(data));
}

export function encodeP256Proof(input: P256ProofInput): Uint8Array {
  if (input.publicKey.length !== 65 || input.publicKey[0] !== 0x04) {
    throw new TypeError("P-256 public key must be uncompressed SEC1");
  }
  if (input.origin.length === 0 || input.origin.length > 0xff) {
    throw new RangeError("origin length");
  }
  if (input.authenticatorData.length < 37) {
    throw new RangeError("authenticator data length");
  }
  if (input.clientDataJson.length === 0 || input.signature.length === 0) {
    throw new RangeError("empty P-256 proof field");
  }

  return bytesConcat(
    input.publicKey,
    Uint8Array.of(input.origin.length),
    input.origin,
    u16le(input.authenticatorData.length),
    input.authenticatorData,
    u16le(input.clientDataJson.length),
    input.clientDataJson,
    u16le(input.signature.length),
    input.signature,
  );
}

export function encodeAccountWitness(
  operation: 1 | 2 | 3,
  sequence: bigint,
  proofs: readonly Proof[],
): Uint8Array {
  requireOperation(operation);
  if (proofs.length > AUTHENTICATOR_MAX_COUNT) {
    throw new RangeError("proof count");
  }

  const encodedProofs: Uint8Array[] = [];
  let previousSlot = -1;
  for (const proof of proofs) {
    if (!Number.isInteger(proof.slot) || proof.slot < 0 || proof.slot > 0xffff) {
      throw new RangeError("proof slot");
    }
    if (proof.slot <= previousSlot) {
      throw new TypeError("proof slots must be unique and ascending");
    }
    if (proof.bytes.length === 0) {
      throw new RangeError("empty proof");
    }
    previousSlot = proof.slot;
    encodedProofs.push(
      bytesConcat(u16le(proof.slot), Uint8Array.of(0, 0), u32le(proof.bytes.length), proof.bytes),
    );
  }

  const encoded = bytesConcat(
    ACCOUNT_WITNESS_MAGIC,
    Uint8Array.of(ACCOUNT_WITNESS_VERSION, operation, proofs.length, 0),
    u64le(sequence),
    ...encodedProofs,
  );
  if (encoded.length > ACCOUNT_WITNESS_MAX_LOCK_LEN) {
    throw new RangeError("AccountWitnessV1 length");
  }
  return encoded;
}

function lengthPrefixed(witness: Uint8Array): Uint8Array {
  return bytesConcat(u64le(BigInt(witness.length)), witness);
}

export function groupSighash(
  txHash: Uint8Array,
  groupWitnesses: readonly Uint8Array[],
  extraWitnesses: readonly Uint8Array[],
): Uint8Array {
  requireLength(txHash, 32, "transaction hash");
  const firstBytes = groupWitnesses[0];
  if (firstBytes === undefined) {
    throw new RangeError("missing group witness");
  }

  const first = WitnessArgs.fromBytes(firstBytes);
  const canonical = WitnessArgs.from({
    lock: "0x",
    inputType: first.inputType,
    outputType: first.outputType,
  }).toBytes();
  return ckbHash(
    bytesConcat(
      txHash,
      lengthPrefixed(canonical),
      ...groupWitnesses.slice(1).map(lengthPrefixed),
      ...extraWitnesses.map(lengthPrefixed),
    ),
  );
}

export function authorizationDigest(input: AuthorizationInput): Uint8Array {
  requireOperation(input.operation);
  requireLength(input.accountId, 32, "account ID");
  requireLength(input.groupSighash, 32, "group sighash");
  return ckbHash(
    bytesConcat(
      AUTH_DOMAIN,
      Uint8Array.of(input.operation),
      input.accountId,
      u64le(input.sequence),
      ckbHash(input.state),
      input.groupSighash,
    ),
  );
}

export function packAccountWitness(witness: Uint8Array): Uint8Array {
  return WitnessArgs.from({ lock: hexFromBytes(witness) }).toBytes();
}

export function unpackAccountWitness(witnessArgs: Uint8Array): Uint8Array {
  const lock = WitnessArgs.fromBytes(witnessArgs).lock;
  if (lock === undefined) {
    throw new TypeError("WitnessArgs lock is absent");
  }
  return bytesFrom(hexFrom(lock));
}
