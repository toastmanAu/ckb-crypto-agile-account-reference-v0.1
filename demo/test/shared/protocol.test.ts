import { WitnessArgs, hexFrom } from "@ckb-ccc/core";
import { describe, expect, it } from "vitest";

import { bytesFromHex, hexFromBytes } from "../../src/shared/bytes.js";
import {
  authorizationDigest,
  ckbHash,
  encodeAccountWitness,
  encodeP256Proof,
  groupSighash,
} from "../../src/shared/protocol.js";
import { frontendVector as vector } from "../fixtures/frontend-v1.js";

const input = vector.inputs;

describe("ABI-v1 browser codec", () => {
  it("matches the Rust P256ProofV1 vector", () => {
    expect(
      hexFromBytes(
        encodeP256Proof({
          publicKey: bytesFromHex(input.public_key),
          origin: bytesFromHex(input.origin),
          authenticatorData: bytesFromHex(input.authenticator_data),
          clientDataJson: bytesFromHex(input.client_data_json),
          signature: bytesFromHex(input.signature),
        }),
      ),
    ).toBe(vector.p256_proof);
  });

  it("matches the Rust AccountWitnessV1 and Molecule vectors", () => {
    const witness = encodeAccountWitness(1, BigInt(input.sequence), [
      { slot: 0, bytes: bytesFromHex(vector.p256_proof) },
    ]);
    expect(hexFromBytes(witness)).toBe(vector.account_witness);
    expect(hexFrom(WitnessArgs.from({ lock: hexFromBytes(witness) }).toBytes())).toBe(
      vector.packed_witness_args,
    );
  });

  it("matches the Rust CKB and authorization hashes", () => {
    expect(hexFromBytes(ckbHash(bytesFromHex(vector.state)))).toBe(vector.state_hash);
    const groupHash = groupSighash(
      bytesFromHex(input.tx_hash),
      [bytesFromHex(vector.packed_witness_args)],
      [],
    );
    expect(hexFromBytes(groupHash)).toBe(vector.group_sighash);
    expect(
      hexFromBytes(
        authorizationDigest({
          operation: 1,
          accountId: bytesFromHex(input.account_id),
          sequence: BigInt(input.sequence),
          state: bytesFromHex(vector.state),
          groupSighash: groupHash,
        }),
      ),
    ).toBe(vector.authorization_digest);
  });
});

describe("consensus-boundary rejection", () => {
  const validP256 = () => ({
    publicKey: bytesFromHex(input.public_key),
    origin: bytesFromHex(input.origin),
    authenticatorData: bytesFromHex(input.authenticator_data),
    clientDataJson: bytesFromHex(input.client_data_json),
    signature: bytesFromHex(input.signature),
  });

  it("rejects invalid P-256 fields and oversized u16 framing", () => {
    expect(() => encodeP256Proof({ ...validP256(), publicKey: new Uint8Array(64) })).toThrow();
    expect(() => encodeP256Proof({ ...validP256(), origin: new Uint8Array(256) })).toThrow();
    expect(() =>
      encodeP256Proof({ ...validP256(), authenticatorData: new Uint8Array(36) }),
    ).toThrow();
    expect(() =>
      encodeP256Proof({ ...validP256(), clientDataJson: new Uint8Array(65_536) }),
    ).toThrow(RangeError);
  });

  it("rejects invalid operations and non-canonical proof slots", () => {
    const proof = { slot: 1, bytes: Uint8Array.of(1) };
    expect(() => encodeAccountWitness(0 as 1, 0n, [proof])).toThrow();
    expect(() => encodeAccountWitness(1, 0n, [proof, proof])).toThrow();
    expect(() =>
      encodeAccountWitness(1, 0n, [proof, { slot: 0, bytes: Uint8Array.of(1) }]),
    ).toThrow();
    expect(() => encodeAccountWitness(1, 0n, new Array(17).fill(proof))).toThrow();
  });

  it("rejects wrong hash sizes and malformed WitnessArgs", () => {
    expect(() => groupSighash(new Uint8Array(31), [Uint8Array.of(1)], [])).toThrow();
    expect(() =>
      groupSighash(new Uint8Array(32), [Uint8Array.of(1, 2, 3)], []),
    ).toThrow();
    expect(() =>
      authorizationDigest({
        operation: 1,
        accountId: new Uint8Array(31),
        sequence: 0n,
        state: Uint8Array.of(1),
        groupSighash: new Uint8Array(32),
      }),
    ).toThrow();
  });
});
