import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { CLIENT_ORIGIN, RP_ID } from "../../src/shared/constants.js";
import {
  PasskeyCancelledError,
  PasskeyProtocolError,
  derivePasskeyAux,
  registerPasskey,
  requestAssertion,
} from "../../src/client/passkey.js";
import type { PasskeyRecord } from "../../src/shared/schemas.js";

const RAW_PUBLIC_KEY = Uint8Array.from(Buffer.from(
  "04" +
    "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296" +
    "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
  "hex",
));
const SPKI = Uint8Array.from(Buffer.from(
  "3059301306072a8648ce3d020106082a8648ce3d030107034200" +
    Buffer.from(RAW_PUBLIC_KEY).toString("hex"),
  "hex",
));
const CREDENTIAL_ID = Uint8Array.of(1, 2, 3, 4);

function arrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.slice().buffer;
}

function registrationCredential() {
  return {
    id: "AQIDBA",
    rawId: arrayBuffer(CREDENTIAL_ID),
    type: "public-key",
    response: {
      getPublicKey: () => arrayBuffer(SPKI),
    },
  } as unknown as PublicKeyCredential;
}

const record: PasskeyRecord = {
  schemaVersion: 1,
  credentialId: "AQIDBA",
  publicKey: `0x${Buffer.from(RAW_PUBLIC_KEY).toString("hex")}`,
  keyId: "0x924617c0c1ca9afcaee0d49ae6ad8b282836c33b9e976d26c7f8b2abb5401893",
  rpId: RP_ID,
  origin: CLIENT_ORIGIN,
  createdAt: "2026-08-24T00:00:00.000Z",
};

describe("browser passkey registration", () => {
  beforeEach(() => {
    vi.stubGlobal("PublicKeyCredential", class PublicKeyCredential {});
    vi.stubGlobal("isSecureContext", true);
  });

  afterEach(() => vi.unstubAllGlobals());

  it("creates an ES256 resident credential and derives its public identifiers", async () => {
    let options: CredentialCreationOptions | undefined;
    const credentials = {
      create: vi.fn(async (received: CredentialCreationOptions) => {
        options = received;
        return registrationCredential();
      }),
    } as unknown as CredentialsContainer;

    const created = await registerPasskey(credentials, crypto);

    expect(options?.publicKey?.rp).toEqual({ id: RP_ID, name: "CKB Passkey Demo" });
    expect(options?.publicKey?.pubKeyCredParams).toContainEqual({ type: "public-key", alg: -7 });
    expect(options?.publicKey?.authenticatorSelection).toMatchObject({
      residentKey: "preferred",
      userVerification: "required",
    });
    expect(created).toMatchObject({
      schemaVersion: 1,
      credentialId: "AQIDBA",
      publicKey: record.publicKey,
      keyId: record.keyId,
      rpId: RP_ID,
      origin: CLIENT_ORIGIN,
    });
    expect(created.createdAt).toMatch(/^\d{4}-\d\d-\d\dT/);
    expect(Buffer.from(created.publicKey.slice(2), "hex")).toHaveLength(65);
    expect(created.publicKey.startsWith("0x04")).toBe(true);
  });

  it("derives aux from SHA-256 of the fixed RP and origin", async () => {
    const rpHash = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(RP_ID)));
    const originHash = new Uint8Array(
      await crypto.subtle.digest("SHA-256", new TextEncoder().encode(CLIENT_ORIGIN)),
    );

    await expect(derivePasskeyAux(crypto)).resolves.toEqual(
      Uint8Array.of(1, ...rpHash, ...originHash),
    );
  });

  it("maps user cancellation to a retryable error", async () => {
    const credentials = {
      create: vi.fn(async () => {
        throw new DOMException("cancelled", "NotAllowedError");
      }),
    } as unknown as CredentialsContainer;

    await expect(registerPasskey(credentials, crypto)).rejects.toBeInstanceOf(
      PasskeyCancelledError,
    );
  });

  it("rejects unsupported and malformed registration responses", async () => {
    vi.stubGlobal("isSecureContext", false);
    const credentials = { create: vi.fn() } as unknown as CredentialsContainer;
    await expect(registerPasskey(credentials, crypto)).rejects.toBeInstanceOf(
      PasskeyProtocolError,
    );

    vi.stubGlobal("isSecureContext", true);
    const malformed = {
      create: vi.fn(async () => ({ ...registrationCredential(), response: {} })),
    } as unknown as CredentialsContainer;
    await expect(registerPasskey(malformed, crypto)).rejects.toBeInstanceOf(
      PasskeyProtocolError,
    );
  });
});

describe("browser passkey assertion", () => {
  beforeEach(() => {
    vi.stubGlobal("PublicKeyCredential", class PublicKeyCredential {});
    vi.stubGlobal("isSecureContext", true);
  });

  afterEach(() => vi.unstubAllGlobals());

  it("requests the exact digest with only the registered credential", async () => {
    const challenge = Uint8Array.from({ length: 32 }, (_, index) => index);
    const authenticatorData = Uint8Array.from({ length: 37 }, (_, index) => index + 1);
    const clientDataJson = new TextEncoder().encode('{"type":"webauthn.get"}');
    const signature = Uint8Array.of(0x30, 0x02, 1, 1);
    let options: CredentialRequestOptions | undefined;
    const credentials = {
      get: vi.fn(async (received: CredentialRequestOptions) => {
        options = received;
        return {
          id: record.credentialId,
          rawId: arrayBuffer(CREDENTIAL_ID),
          type: "public-key",
          response: {
            authenticatorData: arrayBuffer(authenticatorData),
            clientDataJSON: arrayBuffer(clientDataJson),
            signature: arrayBuffer(signature),
          },
        } as unknown as PublicKeyCredential;
      }),
    } as unknown as CredentialsContainer;

    const assertion = await requestAssertion(challenge, record, credentials);
    expect(assertion.credentialId).toBe(record.credentialId);
    expect(Array.from(assertion.authenticatorData)).toEqual(Array.from(authenticatorData));
    expect(Array.from(assertion.clientDataJson)).toEqual(Array.from(clientDataJson));
    expect(Array.from(assertion.signature)).toEqual(Array.from(signature));
    expect(new Uint8Array(options!.publicKey!.challenge as ArrayBuffer)).toEqual(challenge);
    expect(options?.publicKey?.rpId).toBe(RP_ID);
    expect(options?.publicKey?.userVerification).toBe("required");
    expect(options?.publicKey?.allowCredentials).toHaveLength(1);
    expect(new Uint8Array(options!.publicKey!.allowCredentials![0]!.id as ArrayBuffer)).toEqual(
      CREDENTIAL_ID,
    );
  });

  it("rejects non-32-byte challenges and credential substitution", async () => {
    const credentials = {
      get: vi.fn(async () => ({
        ...registrationCredential(),
        rawId: arrayBuffer(Uint8Array.of(9, 9, 9)),
        response: {
          authenticatorData: arrayBuffer(new Uint8Array(37)),
          clientDataJSON: arrayBuffer(Uint8Array.of(1)),
          signature: arrayBuffer(Uint8Array.of(1)),
        },
      })),
    } as unknown as CredentialsContainer;

    await expect(requestAssertion(new Uint8Array(31), record, credentials)).rejects.toThrow(
      "32-byte",
    );
    await expect(requestAssertion(new Uint8Array(32), record, credentials)).rejects.toBeInstanceOf(
      PasskeyProtocolError,
    );
  });
});
