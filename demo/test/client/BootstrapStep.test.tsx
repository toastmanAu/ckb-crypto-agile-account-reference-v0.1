import "@testing-library/jest-dom/vitest";

import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { DemoApiError, type DemoApi } from "../../src/client/api.js";
import { BootstrapStep } from "../../src/client/components/BootstrapStep.js";
import { EXPLORER_URL } from "../../src/shared/constants.js";
import type {
  AccountManifest,
  DemoStatus,
  DeploymentManifest,
  PasskeyRecord,
} from "../../src/shared/schemas.js";

const deployment: DeploymentManifest = {
  schema_version: 1,
  network: "testnet",
  published: true,
  hash_type: "data2",
  artifacts: {
    account_lock: {
      name: "account_lock",
      dataHash: "0xc546913fec9a02ebdf59c7e22e38bd5d9bb07bea81985c4cf8288040f0480abe",
      hashType: "data2",
      txHash: `0x${"11".repeat(32)}`,
      index: 0,
      capacityShannons: "3350900000000",
    },
    verifier_p256: {
      name: "verifier_p256",
      dataHash: "0x376a3e1bfefc57d63cff2e5d022283800fb6b5f014b5edac4be573d58a7b124a",
      hashType: "data2",
      txHash: `0x${"22".repeat(32)}`,
      index: 0,
      capacityShannons: "6218100000000",
    },
  },
};
const status: DemoStatus = {
  schemaVersion: 1,
  network: "testnet",
  origin: "http://localhost:5173",
  rpId: "localhost",
  deploymentVerified: true,
  deployment,
  funderAddress:
    "ckt1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqvcantfhvtwtyzgd4ssn0gjnjhkkl9q9lswhlggn",
  funderBalanceShannons: "19447999686508",
  account: null,
};
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
const account: AccountManifest = {
  schema_version: 1,
  network: "testnet",
  account_id: "0x1c750c0786bc8646d418eddac78a33d0f9be2f24046a1681bd2562feeeb1a7bb",
  account_lock: {
    code_hash: deployment.artifacts.account_lock.dataHash,
    hash_type: "data2",
    args: "0x011c750c0786bc8646d418eddac78a33d0f9be2f24046a1681bd2562feeeb1a7bb",
  },
  type_id_args: `0x${"44".repeat(32)}`,
  state_out_point: { tx_hash: `0x${"33".repeat(32)}`, index: 0 },
  asset_out_point: { tx_hash: `0x${"33".repeat(32)}`, index: 1 },
  state_bytes: 177,
};

function deferred<T>(): { promise: Promise<T>; resolve(value: T): void } {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}

function api(bootstrap: DemoApi["bootstrap"]): DemoApi {
  return {
    bootstrap,
    async status() {
      return status;
    },
    async account() {
      return null;
    },
  };
}

function renderStep(bootstrap: DemoApi["bootstrap"], onCreated = vi.fn()) {
  return render(
    <BootstrapStep
      api={api(bootstrap)}
      status={status}
      passkey={passkey}
      onCreated={onCreated}
    />,
  );
}

describe("BootstrapStep", () => {
  afterEach(cleanup);

  it("reviews the exact funding and verified deployment before exposing one action", () => {
    renderStep(vi.fn());

    expect(screen.getByRole("heading", { name: "Create your testnet account" })).toBeVisible();
    expect(screen.getByText("200 CKB")).toBeVisible();
    expect(screen.getByText(status.funderAddress)).toBeVisible();
    expect(screen.getByText(deployment.artifacts.account_lock.dataHash)).toBeVisible();
    expect(screen.getByText(deployment.artifacts.verifier_p256.dataHash)).toBeVisible();
    expect(screen.getAllByRole("button", { name: "Create testnet account" })).toHaveLength(1);
  });

  it("submits only credential ID and public key and prevents duplicate clicks", async () => {
    const pending = deferred<AccountManifest>();
    const bootstrap = vi.fn(() => pending.promise);
    renderStep(bootstrap);
    const button = screen.getByRole("button", { name: "Create testnet account" });

    fireEvent.click(button);
    fireEvent.click(button);

    expect(bootstrap).toHaveBeenCalledTimes(1);
    expect(bootstrap).toHaveBeenCalledWith({
      credentialId: passkey.credentialId,
      publicKey: passkey.publicKey,
    });
    expect(button).toBeDisabled();
    expect(button).toHaveAttribute("aria-busy", "true");
    expect(screen.getByRole("status")).toHaveTextContent(/submitting account creation/i);
    expect(document.body).not.toHaveTextContent(/0x[0-9a-f]{64}.*submitted/i);
    pending.resolve(account);
    await screen.findByRole("link", { name: /view account creation/i });
  });

  it("accepts a matching idempotent account response and links its real transaction", async () => {
    const onCreated = vi.fn();
    renderStep(vi.fn().mockResolvedValue(account), onCreated);

    fireEvent.click(screen.getByRole("button", { name: "Create testnet account" }));

    await waitFor(() => {
      expect(screen.getByRole("status")).toHaveTextContent(/account creation is committed/i);
    });
    expect(screen.getByRole("link", { name: /view account creation/i })).toHaveAttribute(
      "href",
      `${EXPLORER_URL}${account.state_out_point.tx_hash}`,
    );
    expect(onCreated).toHaveBeenCalledWith(account);
  });

  it("blocks a mismatched existing account without leaking backend detail", async () => {
    const secret = `0x${"ef".repeat(32)}`;
    renderStep(
      vi.fn().mockRejectedValue(new DemoApiError("ACCOUNT_MISMATCH", `Mismatch ${secret}`, 409)),
    );

    fireEvent.click(screen.getByRole("button", { name: "Create testnet account" }));

    expect(await screen.findByRole("alert")).toHaveTextContent(/existing account does not match this passkey/i);
    expect(screen.getByRole("button", { name: "Create testnet account" })).toBeDisabled();
    expect(document.body).not.toHaveTextContent(secret);
  });

  it("shows insufficient balance as safe and retryable", async () => {
    const secret = `0x${"ef".repeat(32)}`;
    renderStep(
      vi.fn().mockRejectedValue(
        new DemoApiError("INSUFFICIENT_BALANCE", `Backend ${secret}`, 409),
      ),
    );

    fireEvent.click(screen.getByRole("button", { name: "Create testnet account" }));

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "The local funder does not have enough CKB",
    );
    expect(screen.getByRole("button", { name: "Create testnet account" })).toBeEnabled();
    expect(document.body).not.toHaveTextContent(secret);
  });

  it.each([
    ["BOOTSTRAP_FAILED", "Account creation may have failed before or after submission"],
    ["API_UNAVAILABLE", "The account request outcome is unknown"],
  ] as const)("blocks resubmission after ambiguous %s failure", async (code, expected) => {
    const secret = `0x${"ef".repeat(32)}`;
    renderStep(vi.fn().mockRejectedValue(new DemoApiError(code, `Backend ${secret}`, 500)));

    fireEvent.click(screen.getByRole("button", { name: "Create testnet account" }));

    expect(await screen.findByRole("alert")).toHaveTextContent(expected);
    expect(screen.getByRole("button", { name: "Create testnet account" })).toBeDisabled();
    expect(document.body).not.toHaveTextContent(secret);
  });

  it("blocks resubmission after a broadcast confirmation timeout", async () => {
    renderStep(
      vi.fn().mockRejectedValue(
        new DemoApiError("CONFIRMATION_TIMEOUT", "internal node timeout detail", 504),
      ),
    );

    fireEvent.click(screen.getByRole("button", { name: "Create testnet account" }));

    expect(await screen.findByRole("alert")).toHaveTextContent(/may have been submitted.*restart the local demo/i);
    expect(screen.getByRole("button", { name: "Create testnet account" })).toBeDisabled();
    expect(document.body).not.toHaveTextContent("internal node timeout detail");
  });
});
