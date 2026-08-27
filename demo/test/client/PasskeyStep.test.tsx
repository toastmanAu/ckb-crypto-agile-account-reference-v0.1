import "@testing-library/jest-dom/vitest";

import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { PasskeyStep } from "../../src/client/components/PasskeyStep.js";
import {
  PasskeyCancelledError,
  PasskeyProtocolError,
  type registerPasskey,
} from "../../src/client/passkey.js";
import { PASSKEY_STORAGE_KEY } from "../../src/client/storage.js";
import type { PasskeyRecord } from "../../src/shared/schemas.js";

const passkey: PasskeyRecord = {
  schemaVersion: 1,
  credentialId: "AQIDBA",
  publicKey:
    "0x046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
  keyId: "0x924617c0c1ca9afcaee0d49ae6ad8b282836c33b9e976d26c7f8b2abb5401893",
  rpId: "localhost",
  origin: "http://localhost:5173",
  createdAt: "2026-08-24T00:00:00.000Z",
};

function deferred<T>(): { promise: Promise<T>; resolve(value: T): void } {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}

function renderStep(
  register: typeof registerPasskey,
  onCreated: (record: PasskeyRecord) => void = vi.fn(),
) {
  return render(
    <PasskeyStep
      storage={localStorage}
      credentials={{} as CredentialsContainer}
      cryptoProvider={{} as Crypto}
      register={register}
      onCreated={onCreated}
    />,
  );
}

describe("PasskeyStep", () => {
  beforeEach(() => {
    localStorage.clear();
    vi.stubGlobal("isSecureContext", true);
    vi.stubGlobal("PublicKeyCredential", class PublicKeyCredential {});
    vi.stubGlobal(
      "AuthenticatorAttestationResponse",
      class AuthenticatorAttestationResponse {
        getPublicKey(): ArrayBuffer | null {
          return null;
        }
      },
    );
  });

  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it("reviews the browser ceremony and public-only storage boundary", () => {
    renderStep(vi.fn());

    expect(screen.getByRole("heading", { name: "Create your passkey" })).toBeVisible();
    expect(screen.getByText(/device-bound P-256 credential/i)).toBeVisible();
    expect(screen.getByText(/only.*public key.*credential ID/i)).toBeVisible();
    expect(screen.getByText(/does not expose.*private key/i)).toBeVisible();
    expect(screen.getAllByRole("button", { name: "Create passkey" })).toHaveLength(1);
  });

  it("explains unsupported browser capabilities and offers no action", () => {
    vi.stubGlobal("isSecureContext", false);
    renderStep(vi.fn());

    expect(screen.getByRole("alert")).toHaveTextContent(/secure localhost.*Chromium/i);
    expect(screen.queryByRole("button", { name: "Create passkey" })).not.toBeInTheDocument();
  });

  it("disables the same primary control and announces registration while pending", async () => {
    const pending = deferred<PasskeyRecord>();
    renderStep(vi.fn(() => pending.promise));
    const button = screen.getByRole("button", { name: "Create passkey" });

    fireEvent.click(button);

    expect(button).toBeDisabled();
    expect(button).toHaveAttribute("aria-busy", "true");
    expect(screen.getByRole("status")).toHaveTextContent(/waiting for your browser/i);
    expect(screen.getByRole("button", { name: "Creating passkey" })).toBe(button);
    pending.resolve(passkey);
    await screen.findByText(passkey.keyId);
  });

  it("returns cancellation to a retryable ready state without writing storage", async () => {
    const register = vi.fn().mockRejectedValue(new PasskeyCancelledError());
    renderStep(register);

    fireEvent.click(screen.getByRole("button", { name: "Create passkey" }));

    await waitFor(() => {
      expect(screen.getByRole("status")).toHaveTextContent("Passkey creation was cancelled");
    });
    expect(screen.getByRole("button", { name: "Create passkey" })).toBeEnabled();
    expect(localStorage.getItem(PASSKEY_STORAGE_KEY)).toBeNull();
  });

  it("validates, stores, displays, and announces public passkey metadata before notifying its parent", async () => {
    const onCreated = vi.fn();
    renderStep(vi.fn().mockResolvedValue(passkey), onCreated);

    fireEvent.click(screen.getByRole("button", { name: "Create passkey" }));

    expect(await screen.findByText(passkey.publicKey)).toBeVisible();
    expect(screen.getByText(passkey.keyId)).toBeVisible();
    expect(screen.getByRole("status")).toHaveTextContent(/passkey public metadata is saved/i);
    expect(JSON.parse(localStorage.getItem(PASSKEY_STORAGE_KEY) ?? "null")).toEqual(passkey);
    expect(onCreated).toHaveBeenCalledWith(passkey);
    expect(JSON.stringify(onCreated.mock.calls)).not.toContain("privateKey");
  });

  it("blocks malformed registration results before storage or parent notification", async () => {
    const onCreated = vi.fn();
    const malformed = { ...passkey, privateKey: `0x${"ef".repeat(32)}` } as PasskeyRecord;
    renderStep(vi.fn().mockResolvedValue(malformed), onCreated);

    fireEvent.click(screen.getByRole("button", { name: "Create passkey" }));

    expect(await screen.findByRole("alert")).toHaveTextContent(/did not return valid public metadata/i);
    expect(screen.getByRole("button", { name: "Create passkey" })).toBeDisabled();
    expect(localStorage.getItem(PASSKEY_STORAGE_KEY)).toBeNull();
    expect(onCreated).not.toHaveBeenCalled();
    expect(document.body).not.toHaveTextContent("ef".repeat(32));
  });

  it("treats protocol failures as blocking compatibility errors", async () => {
    renderStep(vi.fn().mockRejectedValue(new PasskeyProtocolError("raw authenticator detail")));

    fireEvent.click(screen.getByRole("button", { name: "Create passkey" }));

    expect(await screen.findByRole("alert")).toHaveTextContent(/browser returned an incompatible passkey response/i);
    expect(screen.getByRole("button", { name: "Create passkey" })).toBeDisabled();
    expect(document.body).not.toHaveTextContent("raw authenticator detail");
  });
});
