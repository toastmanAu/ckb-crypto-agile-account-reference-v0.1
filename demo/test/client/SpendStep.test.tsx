import "@testing-library/jest-dom/vitest";

import { ccc } from "@ckb-ccc/core";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  SpendStep,
  type SpendStepOperations,
} from "../../src/client/components/SpendStep.js";
import type { PreparedSpend, SpendClient } from "../../src/client/chain.js";
import { PasskeyCancelledError, type AssertionMaterial } from "../../src/client/passkey.js";
import type {
  CommittedReceipt,
  PasskeyRecord,
  SubmittedReceipt,
} from "../../src/shared/schemas.js";

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
const txHash = `0x${"aa".repeat(32)}` as const;
const submitted: SubmittedReceipt = {
  status: "submitted",
  txHash,
  explorerUrl: `https://pudge.explorer.nervos.org/transaction/${txHash}`,
  remainingCapacityShannons: "9999900000",
};
const committed: CommittedReceipt = { ...submitted, status: "committed" };
const assertion: AssertionMaterial = {
  credentialId: passkey.credentialId,
  authenticatorData: new Uint8Array(37),
  clientDataJson: new TextEncoder().encode("{}"),
  signature: Uint8Array.of(0x30, 0x06, 0x02, 0x01, 1, 0x02, 0x01, 1),
};

function deferred<T>(): { promise: Promise<T>; resolve(value: T): void } {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}

function preparedSpend(): PreparedSpend {
  const lock = {
    codeHash: `0x${"11".repeat(32)}`,
    hashType: "type" as const,
    args: `0x${"22".repeat(20)}`,
  };
  return {
    transaction: ccc.Transaction.from({
      inputs: [{ previousOutput: { txHash: `0x${"44".repeat(32)}`, index: 1 } }],
      outputs: [
        { capacity: 10_000_000_000n, lock },
        { capacity: 9_999_900_000n, lock },
      ],
      outputsData: ["0x", "0x"],
      witnesses: ["0x"],
    }),
    authorizationDigest: Uint8Array.from({ length: 32 }, (_, index) => index),
    review: {
      inputCapacityShannons: "20000000000",
      transferCapacityShannons: "10000000000",
      changeCapacityShannons: "9999900000",
      feeShannons: "100000",
      funderAddress: "ckt1funder",
      inputOutPoint: { txHash: `0x${"33".repeat(32)}`, index: 1 },
      dependencies: [
        { name: "account_lock", txHash: `0x${"11".repeat(32)}`, index: 0 },
        { name: "verifier_p256", txHash: `0x${"22".repeat(32)}`, index: 0 },
        { name: "account_state", txHash: `0x${"33".repeat(32)}`, index: 0 },
      ],
    },
    maxWitnessBytes: 4096,
    sequence: 0n,
    credentialId: passkey.credentialId,
    publicKey: passkey.publicKey,
    accountId: `0x${"55".repeat(32)}`,
    stateData: "0x00",
  };
}

function operations(overrides: Partial<SpendStepOperations> = {}): SpendStepOperations {
  return {
    prepare: vi.fn().mockResolvedValue(preparedSpend()),
    requestAssertion: vi.fn().mockResolvedValue(assertion),
    finalize: vi.fn((prepared) => prepared.transaction.clone()),
    submit: vi.fn().mockResolvedValue(submitted),
    confirm: vi.fn().mockResolvedValue(committed),
    ...overrides,
  };
}

function renderStep(
  spendOperations: SpendStepOperations,
  onReceipt = vi.fn(),
) {
  return render(
    <SpendStep
      client={{} as SpendClient}
      account={{} as never}
      funderAddress="ckt1funder"
      passkey={passkey}
      credentials={{} as CredentialsContainer}
      operations={spendOperations}
      onReceipt={onReceipt}
    />,
  );
}

describe("SpendStep", () => {
  afterEach(cleanup);

  it("offers no authorization action before live discovery and preparation finish", async () => {
    const pending = deferred<PreparedSpend>();
    renderStep(operations({ prepare: vi.fn(() => pending.promise) }));

    expect(screen.getByRole("status")).toHaveTextContent(/discovering.*account cells/i);
    expect(screen.queryByRole("button", { name: /authorize/i })).not.toBeInTheDocument();

    pending.resolve(preparedSpend());
    expect(await screen.findByRole("button", { name: "Authorize 100 CKB spend" })).toBeEnabled();
  });

  it("renders the exact capacity, fee, digest, input, and three dependency identities", async () => {
    renderStep(operations());

    expect(await screen.findByText("200 CKB")).toBeVisible();
    expect(screen.getByText("100 CKB")).toBeVisible();
    expect(screen.getByText("99.999 CKB")).toBeVisible();
    expect(screen.getByText("0.001 CKB")).toBeVisible();
    expect(screen.getByText(`0x${"33".repeat(32)}:1`)).toBeVisible();
    expect(screen.getByText(`0x${Array.from({ length: 32 }, (_, index) => index.toString(16).padStart(2, "0")).join("")}`)).toBeVisible();
    expect(screen.getByText(/AccountLock code/i)).toBeVisible();
    expect(screen.getByText(/P-256 verifier code/i)).toBeVisible();
    expect(screen.getByText(/AccountState cell/i)).toBeVisible();
    expect(screen.getAllByRole("button", { name: "Authorize 100 CKB spend" })).toHaveLength(1);
  });

  it("returns passkey cancellation to the frozen review without submitting", async () => {
    const spendOperations = operations({
      requestAssertion: vi.fn().mockRejectedValue(new PasskeyCancelledError()),
    });
    renderStep(spendOperations);
    fireEvent.click(await screen.findByRole("button", { name: "Authorize 100 CKB spend" }));

    await waitFor(() => {
      expect(screen.getByRole("status")).toHaveTextContent("Passkey authorization was cancelled");
    });
    expect(screen.getByRole("button", { name: "Authorize 100 CKB spend" })).toBeEnabled();
    expect(spendOperations.submit).not.toHaveBeenCalled();
  });

  it("blocks credential substitution before submission", async () => {
    const spendOperations = operations({
      finalize: vi.fn(() => {
        throw new TypeError("Assertion credential does not match the prepared spend");
      }),
    });
    renderStep(spendOperations);
    fireEvent.click(await screen.findByRole("button", { name: "Authorize 100 CKB spend" }));

    expect(await screen.findByRole("alert")).toHaveTextContent(/credential did not match.*reviewed spend/i);
    expect(screen.getByRole("button", { name: "Authorize 100 CKB spend" })).toBeDisabled();
    expect(spendOperations.submit).not.toHaveBeenCalled();
  });

  it("blocks if any raw transaction field changes while WebAuthn is open", async () => {
    const prepared = preparedSpend();
    const spendOperations = operations({
      prepare: vi.fn().mockResolvedValue(prepared),
      requestAssertion: vi.fn(async () => {
        prepared.transaction.outputs[0]!.capacity -= 1n;
        return assertion;
      }),
    });
    renderStep(spendOperations);
    fireEvent.click(await screen.findByRole("button", { name: "Authorize 100 CKB spend" }));

    expect(await screen.findByRole("alert")).toHaveTextContent(/transaction changed while passkey authorization was open/i);
    expect(spendOperations.finalize).not.toHaveBeenCalled();
    expect(spendOperations.submit).not.toHaveBeenCalled();
  });

  it("uses the exact prepared digest and prevents duplicate authorization or submission", async () => {
    const assertionPending = deferred<AssertionMaterial>();
    const spendOperations = operations({
      requestAssertion: vi.fn(() => assertionPending.promise),
      confirm: vi.fn(() => new Promise<never>(() => undefined)),
    });
    const onReceipt = vi.fn();
    renderStep(spendOperations, onReceipt);
    const button = await screen.findByRole("button", { name: "Authorize 100 CKB spend" });

    fireEvent.click(button);
    fireEvent.click(button);

    expect(spendOperations.requestAssertion).toHaveBeenCalledTimes(1);
    expect(spendOperations.requestAssertion).toHaveBeenCalledWith(
      expect.objectContaining({ 0: 0, 31: 31 }),
      passkey,
      expect.anything(),
    );
    expect(button).toBeDisabled();
    assertionPending.resolve(assertion);
    await waitFor(() => expect(onReceipt).toHaveBeenCalledWith(submitted));
    expect(spendOperations.submit).toHaveBeenCalledTimes(1);
  });

  it("publishes submitted state before confirmation and then the verified committed receipt", async () => {
    const confirmation = deferred<CommittedReceipt>();
    const spendOperations = operations({ confirm: vi.fn(() => confirmation.promise) });
    const onReceipt = vi.fn();
    renderStep(spendOperations, onReceipt);
    fireEvent.click(await screen.findByRole("button", { name: "Authorize 100 CKB spend" }));

    await waitFor(() => expect(onReceipt).toHaveBeenNthCalledWith(1, submitted));
    confirmation.resolve(committed);
    await waitFor(() => expect(onReceipt).toHaveBeenNthCalledWith(2, committed));
  });
});
