import { bytesConcat, hexFromBytes } from "../shared/bytes.js";
import { CLIENT_ORIGIN, RP_ID } from "../shared/constants.js";
import { ckbHash } from "../shared/protocol.js";
import {
  PasskeyRecordSchema,
  type PasskeyRecord,
} from "../shared/schemas.js";

const ES256 = -7;
const CHALLENGE_BYTES = 32;
const USER_HANDLE_BYTES = 32;
const PUBLIC_KEY_BYTES = 65;

export interface AssertionMaterial {
  credentialId: string;
  authenticatorData: Uint8Array;
  clientDataJson: Uint8Array;
  signature: Uint8Array;
}

export class PasskeyCancelledError extends Error {
  constructor() {
    super("Passkey operation was cancelled");
    this.name = "PasskeyCancelledError";
  }
}

export class PasskeyProtocolError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PasskeyProtocolError";
  }
}

function requireWebAuthn(): void {
  if (globalThis.isSecureContext !== true) {
    throw new PasskeyProtocolError("Passkeys require a secure localhost context");
  }
  if (typeof globalThis.PublicKeyCredential !== "function") {
    throw new PasskeyProtocolError("PublicKeyCredential is unavailable");
  }
}

function randomBytes(cryptoProvider: Crypto, length: number): Uint8Array {
  return cryptoProvider.getRandomValues(new Uint8Array(length));
}

function ownedBuffer(bytes: Uint8Array): ArrayBuffer {
  const buffer = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(buffer).set(bytes);
  return buffer;
}

function base64urlEncode(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

function base64urlDecode(value: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new PasskeyProtocolError("Credential ID is not canonical base64url");
  }
  const padded = value.replaceAll("-", "+").replaceAll("_", "/").padEnd(
    Math.ceil(value.length / 4) * 4,
    "=",
  );
  try {
    const binary = atob(padded);
    const decoded = Uint8Array.from(binary, (character) => character.charCodeAt(0));
    if (decoded.length === 0 || base64urlEncode(decoded) !== value) {
      throw new Error("non-canonical");
    }
    return decoded;
  } catch {
    throw new PasskeyProtocolError("Credential ID is not canonical base64url");
  }
}

function bytesFromBuffer(value: unknown, label: string): Uint8Array {
  if (Object.prototype.toString.call(value) !== "[object ArrayBuffer]") {
    throw new PasskeyProtocolError(`${label} is missing`);
  }
  return new Uint8Array(value as ArrayBuffer).slice();
}

function isCancellation(error: unknown): boolean {
  return error instanceof DOMException && error.name === "NotAllowedError";
}

async function rawPublicKeyFromSpki(
  spki: Uint8Array,
  cryptoProvider: Crypto,
): Promise<Uint8Array> {
  let imported: CryptoKey;
  try {
    imported = await cryptoProvider.subtle.importKey(
      "spki",
      ownedBuffer(spki),
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["verify"],
    );
  } catch {
    throw new PasskeyProtocolError("Registration public key is not ES256/P-256");
  }
  const raw = new Uint8Array(await cryptoProvider.subtle.exportKey("raw", imported));
  if (raw.length !== PUBLIC_KEY_BYTES || raw[0] !== 0x04) {
    throw new PasskeyProtocolError("Registration public key is not uncompressed P-256");
  }
  return raw;
}

export async function derivePasskeyAux(cryptoProvider: Crypto): Promise<Uint8Array> {
  const encoder = new TextEncoder();
  const [rpIdHash, originHash] = await Promise.all([
    cryptoProvider.subtle.digest("SHA-256", ownedBuffer(encoder.encode(RP_ID))),
    cryptoProvider.subtle.digest("SHA-256", ownedBuffer(encoder.encode(CLIENT_ORIGIN))),
  ]);
  return bytesConcat(Uint8Array.of(1), new Uint8Array(rpIdHash), new Uint8Array(originHash));
}

export async function registerPasskey(
  credentials: CredentialsContainer,
  cryptoProvider: Crypto,
): Promise<PasskeyRecord> {
  requireWebAuthn();
  try {
    const created = await credentials.create({
      publicKey: {
        challenge: ownedBuffer(randomBytes(cryptoProvider, CHALLENGE_BYTES)),
        rp: { id: RP_ID, name: "CKB Passkey Demo" },
        user: {
          id: ownedBuffer(randomBytes(cryptoProvider, USER_HANDLE_BYTES)),
          name: "local-passkey-user",
          displayName: "Local passkey user",
        },
        pubKeyCredParams: [{ type: "public-key", alg: ES256 }],
        authenticatorSelection: {
          residentKey: "preferred",
          userVerification: "required",
        },
        attestation: "none",
      },
    });
    if (created === null || created.type !== "public-key") {
      throw new PasskeyProtocolError("Registration did not return a public-key credential");
    }
    const publicKeyCredential = created as PublicKeyCredential;

    const credentialId = base64urlEncode(
      bytesFromBuffer(publicKeyCredential.rawId, "Credential ID"),
    );
    if (created.id !== credentialId) {
      throw new PasskeyProtocolError("Registration credential ID is inconsistent");
    }
    const response = publicKeyCredential.response as AuthenticatorAttestationResponse;
    if (typeof response?.getPublicKey !== "function") {
      throw new PasskeyProtocolError("Authenticator cannot export the registration public key");
    }
    const publicKeySpki = response.getPublicKey();
    if (publicKeySpki === null) {
      throw new PasskeyProtocolError("Authenticator returned no registration public key");
    }
    const publicKey = await rawPublicKeyFromSpki(new Uint8Array(publicKeySpki), cryptoProvider);
    await derivePasskeyAux(cryptoProvider);

    return PasskeyRecordSchema.parse({
      schemaVersion: 1,
      credentialId,
      publicKey: hexFromBytes(publicKey),
      keyId: hexFromBytes(ckbHash(publicKey)),
      rpId: RP_ID,
      origin: CLIENT_ORIGIN,
      createdAt: new Date().toISOString(),
    });
  } catch (error) {
    if (isCancellation(error)) {
      throw new PasskeyCancelledError();
    }
    if (error instanceof PasskeyProtocolError) {
      throw error;
    }
    throw new PasskeyProtocolError("Malformed passkey registration response");
  }
}

export async function requestAssertion(
  challenge: Uint8Array,
  recordValue: PasskeyRecord,
  credentials: CredentialsContainer,
): Promise<AssertionMaterial> {
  requireWebAuthn();
  if (challenge.length !== CHALLENGE_BYTES) {
    throw new PasskeyProtocolError("Authorization challenge must be exactly 32-byte");
  }
  const record = PasskeyRecordSchema.parse(recordValue);
  const allowedCredentialId = base64urlDecode(record.credentialId);

  try {
    const assertion = await credentials.get({
      publicKey: {
        challenge: ownedBuffer(challenge),
        rpId: RP_ID,
        allowCredentials: [{
          type: "public-key",
          id: ownedBuffer(allowedCredentialId),
        }],
        userVerification: "required",
      },
    });
    if (assertion === null || assertion.type !== "public-key") {
      throw new PasskeyProtocolError("Assertion did not return a public-key credential");
    }
    const publicKeyCredential = assertion as PublicKeyCredential;
    const credentialId = base64urlEncode(
      bytesFromBuffer(publicKeyCredential.rawId, "Credential ID"),
    );
    if (credentialId !== record.credentialId || assertion.id !== credentialId) {
      throw new PasskeyProtocolError("Assertion used an unexpected credential");
    }
    const response = publicKeyCredential.response as AuthenticatorAssertionResponse;
    const authenticatorData = bytesFromBuffer(response?.authenticatorData, "Authenticator data");
    const clientDataJson = bytesFromBuffer(response?.clientDataJSON, "Client data JSON");
    const signature = bytesFromBuffer(response?.signature, "Assertion signature");
    if (authenticatorData.length < 37 || clientDataJson.length === 0 || signature.length === 0) {
      throw new PasskeyProtocolError("Assertion response fields are malformed");
    }
    return { credentialId, authenticatorData, clientDataJson, signature };
  } catch (error) {
    if (isCancellation(error)) {
      throw new PasskeyCancelledError();
    }
    if (error instanceof PasskeyProtocolError) {
      throw error;
    }
    throw new PasskeyProtocolError("Malformed passkey assertion response");
  }
}
