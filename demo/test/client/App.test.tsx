import "@testing-library/jest-dom/vitest";

import { ccc } from "@ckb-ccc/core";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { App } from "../../src/client/App.js";
import type { DemoApi } from "../../src/client/api.js";
import type { PreparedSpend, SpendClient } from "../../src/client/chain.js";
import type { SpendStepOperations } from "../../src/client/components/SpendStep.js";
import type { registerPasskey } from "../../src/client/passkey.js";
import { PASSKEY_STORAGE_KEY } from "../../src/client/storage.js";
import type {
  AccountManifest,
  DemoStatus,
  DeploymentManifest,
  PasskeyRecord,
  SubmittedReceipt,
  TransactionReceipt,
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
const spendClient = {} as SpendClient;
const spendTxHash = `0x${"aa".repeat(32)}` as const;
const submittedReceipt: SubmittedReceipt = {
  status: "submitted",
  txHash: spendTxHash,
  explorerUrl: `https://pudge.explorer.nervos.org/transaction/${spendTxHash}`,
  remainingCapacityShannons: "9999900000",
};

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
    authorizationDigest: new Uint8Array(32),
    review: {
      inputCapacityShannons: "20000000000",
      transferCapacityShannons: "10000000000",
      changeCapacityShannons: "9999900000",
      feeShannons: "100000",
      funderAddress: status.funderAddress,
      inputOutPoint: { txHash: account.asset_out_point.tx_hash, index: 1 },
      dependencies: [
        { name: "account_lock", txHash: deployment.artifacts.account_lock.txHash, index: 0 },
        { name: "verifier_p256", txHash: deployment.artifacts.verifier_p256.txHash, index: 0 },
        { name: "account_state", txHash: account.state_out_point.tx_hash, index: 0 },
      ],
    },
    maxWitnessBytes: 4096,
    sequence: 0n,
    credentialId: passkey.credentialId,
    publicKey: passkey.publicKey,
    accountId: account.account_id,
    stateData: "0x00",
  };
}

function spendOperations(
  confirm: SpendStepOperations["confirm"] = vi.fn().mockResolvedValue({
    ...submittedReceipt,
    status: "committed",
  }),
): SpendStepOperations {
  return {
    prepare: vi.fn().mockResolvedValue(preparedSpend()),
    requestAssertion: vi.fn().mockResolvedValue({
      credentialId: passkey.credentialId,
      authenticatorData: new Uint8Array(37),
      clientDataJson: new TextEncoder().encode("{}"),
      signature: Uint8Array.of(0x30, 0x06, 0x02, 0x01, 1, 0x02, 0x01, 1),
    }),
    finalize: vi.fn((prepared) => prepared.transaction.clone()),
    submit: vi.fn().mockResolvedValue(submittedReceipt),
    confirm,
  };
}

function api(currentStatus: DemoStatus, currentAccount: AccountManifest | null): DemoApi {
  return {
    async status() {
      return currentStatus;
    },
    async account() {
      return currentAccount;
    },
    async bootstrap() {
      throw new Error("not used by the Task 9 shell");
    },
  };
}

function storePasskey(): void {
  localStorage.setItem(PASSKEY_STORAGE_KEY, JSON.stringify(passkey));
}

function enabledPrimaryActions(): HTMLElement[] {
  return Array.from(document.querySelectorAll<HTMLElement>(".primary-action:not(:disabled)"));
}

describe("passkey demo wizard shell", () => {
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

  it("shows an explicit loading state while both authoritative API reads are pending", () => {
    const pending = new Promise<never>(() => undefined);
    render(<App api={{ status: () => pending, account: () => pending, bootstrap: () => pending }} storage={localStorage} />);

    expect(screen.getByRole("status")).toHaveTextContent("Checking local services");
    expect(screen.getByRole("heading", { name: "Preparing your account" })).toBeInTheDocument();
    expect(enabledPrimaryActions()).toHaveLength(0);
  });

  it("keeps the testnet, localhost, and unaudited safety labels visible", async () => {
    render(<App api={api(status, null)} storage={localStorage} />);

    expect(await screen.findByRole("heading", { name: "Create your passkey" })).toBeInTheDocument();
    expect(screen.getByText("CKB testnet")).toBeVisible();
    expect(screen.getByText("localhost")).toBeVisible();
    expect(screen.getByText("Unaudited reference")).toBeVisible();
    expect(screen.getByText(status.funderAddress)).toBeVisible();
    expect(screen.getByText("194,479.99686508 CKB")).toBeVisible();
  });

  it("blocks unsupported browsers with an actionable compatibility explanation", async () => {
    vi.stubGlobal("isSecureContext", false);
    render(<App api={api(status, null)} storage={localStorage} />);

    expect(await screen.findByRole("heading", { name: "Passkeys are unavailable" })).toBeVisible();
    expect(screen.getByRole("alert")).toHaveTextContent(/secure localhost.*Chromium/i);
    expect(enabledPrimaryActions()).toHaveLength(0);
  });

  it("selects passkey, account, and spend steps from browser and server state", async () => {
    const view = render(<App api={api(status, null)} storage={localStorage} />);
    expect(await screen.findByRole("button", { name: "Create passkey" })).toBeEnabled();
    expect(enabledPrimaryActions()).toHaveLength(1);

    cleanup();
    storePasskey();
    render(<App api={api(status, null)} storage={localStorage} />);
    expect(await screen.findByRole("button", { name: "Create testnet account" })).toBeEnabled();
    expect(enabledPrimaryActions()).toHaveLength(1);

    cleanup();
    render(
      <App
        api={api({ ...status, account }, account)}
        storage={localStorage}
        chainClient={spendClient}
        spendOperations={spendOperations()}
      />,
    );
    expect(await screen.findByRole("button", { name: "Authorize 100 CKB spend" })).toBeEnabled();
    expect(enabledPrimaryActions()).toHaveLength(1);
    view.unmount();
  });

  it("blocks missing local credentials and inconsistent server snapshots", async () => {
    render(<App api={api({ ...status, account }, account)} storage={localStorage} />);
    expect(await screen.findByRole("heading", { name: "Account access is blocked" })).toBeVisible();
    expect(screen.getByRole("alert")).toHaveTextContent(/local passkey metadata is missing/i);
    expect(enabledPrimaryActions()).toHaveLength(0);

    cleanup();
    storePasskey();
    render(<App api={api({ ...status, account: null }, account)} storage={localStorage} />);
    expect(await screen.findByRole("alert")).toHaveTextContent(/server account state changed/i);
    expect(enabledPrimaryActions()).toHaveLength(0);
  });

  it("surfaces only safe API errors in a blocking live region", async () => {
    const secret = `0x${"ef".repeat(32)}`;
    const failing: DemoApi = {
      async status() {
        throw new Error(`backend failed with ${secret}`);
      },
      async account() {
        return null;
      },
      async bootstrap() {
        throw new Error("unused");
      },
    };
    render(<App api={failing} storage={localStorage} />);

    expect(await screen.findByRole("alert")).toHaveTextContent("Local API is unavailable");
    expect(document.body).not.toHaveTextContent(secret);
  });

  it("represents submitted and committed receipt states without treating timeout as failure", async () => {
    storePasskey();
    const receipt = {
      txHash: `0x${"aa".repeat(32)}`,
      explorerUrl: `https://pudge.explorer.nervos.org/transaction/0x${"aa".repeat(32)}`,
      remainingCapacityShannons: "9999999000",
    };
    const readyApi = api({ ...status, account }, account);
    const view = render(
      <App
        api={readyApi}
        storage={localStorage}
        chainClient={spendClient}
        spendOperations={spendOperations()}
        receipt={{ ...receipt, status: "confirmation_timeout" } as TransactionReceipt}
      />,
    );
    expect(await screen.findByRole("heading", { name: "Transaction submitted" })).toBeVisible();
    expect(screen.getByRole("status")).toHaveTextContent(/confirmation is taking longer/i);
    expect(screen.queryByText(/failed/i)).not.toBeInTheDocument();

    view.rerender(
      <App
        api={readyApi}
        storage={localStorage}
        chainClient={spendClient}
        spendOperations={spendOperations()}
        receipt={{ ...receipt, status: "committed" } as TransactionReceipt}
      />,
    );
    expect(await screen.findByRole("heading", { name: "Spend committed" })).toBeVisible();
  });

  it("lets a recheck advance a hydrated timeout receipt to committed", async () => {
    storePasskey();
    const operations = spendOperations();
    render(
      <App
        api={api({ ...status, account }, account)}
        storage={localStorage}
        chainClient={spendClient}
        spendOperations={operations}
        receipt={{ ...submittedReceipt, status: "confirmation_timeout" }}
      />,
    );

    fireEvent.click(await screen.findByRole("button", { name: "Check again" }));

    expect(await screen.findByRole("heading", { name: "Spend committed" })).toBeVisible();
    expect(operations.submit).not.toHaveBeenCalled();
  });

  it("does not let a receipt hide an authoritative account reconciliation block", async () => {
    storePasskey();
    render(
      <App
        api={api({ ...status, account: null }, account)}
        storage={localStorage}
        chainClient={spendClient}
        spendOperations={spendOperations()}
        receipt={{
          status: "submitted",
          txHash: `0x${"aa".repeat(32)}`,
          explorerUrl: `https://pudge.explorer.nervos.org/transaction/0x${"aa".repeat(32)}`,
          remainingCapacityShannons: "9999999000",
        }}
      />,
    );

    expect(await screen.findByRole("heading", { name: "Account access is blocked" })).toBeVisible();
    expect(screen.getByRole("alert")).toHaveTextContent(/server account state changed/i);
  });

  it("stores a validated registration and advances to account bootstrap", async () => {
    const register = vi.fn<typeof registerPasskey>().mockResolvedValue(passkey);
    render(
      <App
        api={api(status, null)}
        storage={localStorage}
        credentials={{} as CredentialsContainer}
        cryptoProvider={{} as Crypto}
        register={register}
      />,
    );

    fireEvent.click(await screen.findByRole("button", { name: "Create passkey" }));

    const accountHeading = await screen.findByRole("heading", { name: "Create your testnet account" });
    expect(accountHeading).toHaveFocus();
    expect(JSON.parse(localStorage.getItem(PASSKEY_STORAGE_KEY) ?? "null")).toEqual(passkey);
    expect(screen.getByText(passkey.keyId)).toBeVisible();
  });

  it("re-fetches status and account after bootstrap before enabling spend", async () => {
    storePasskey();
    let bootstrapped = false;
    const integratedApi: DemoApi = {
      status: vi.fn(async () => ({ ...status, account: bootstrapped ? account : null })),
      account: vi.fn(async () => (bootstrapped ? account : null)),
      bootstrap: vi.fn(async () => {
        bootstrapped = true;
        return account;
      }),
    };
    render(
      <App
        api={integratedApi}
        storage={localStorage}
        chainClient={spendClient}
        spendOperations={spendOperations()}
      />,
    );

    fireEvent.click(await screen.findByRole("button", { name: "Create testnet account" }));

    const spendHeading = await screen.findByRole("heading", { name: "Authorize your first spend" });
    expect(spendHeading).toHaveFocus();
    expect(integratedApi.status).toHaveBeenCalledTimes(2);
    expect(integratedApi.account).toHaveBeenCalledTimes(2);
    expect(integratedApi.bootstrap).toHaveBeenCalledWith({
      credentialId: passkey.credentialId,
      publicKey: passkey.publicKey,
    });
  });

  it("blocks when post-bootstrap authoritative snapshots disagree", async () => {
    storePasskey();
    const integratedApi: DemoApi = {
      status: vi.fn(async () => status),
      account: vi.fn()
        .mockResolvedValueOnce(null)
        .mockResolvedValueOnce(account),
      bootstrap: vi.fn().mockResolvedValue(account),
    };
    render(<App api={integratedApi} storage={localStorage} />);

    fireEvent.click(await screen.findByRole("button", { name: "Create testnet account" }));

    expect(await screen.findByRole("heading", { name: "Account access is blocked" })).toBeVisible();
    expect(screen.getByRole("alert")).toHaveTextContent(/server account state changed/i);
    expect(enabledPrimaryActions()).toHaveLength(0);
  });

  it("moves from the frozen spend review to submitted and then committed receipt states", async () => {
    storePasskey();
    let finishConfirmation!: (receipt: TransactionReceipt) => void;
    const confirmation = new Promise<TransactionReceipt>((resolve) => {
      finishConfirmation = resolve;
    });
    const operations = spendOperations(vi.fn(() => confirmation) as SpendStepOperations["confirm"]);
    render(
      <App
        api={api({ ...status, account }, account)}
        storage={localStorage}
        chainClient={spendClient}
        spendOperations={operations}
        credentials={{} as CredentialsContainer}
      />,
    );

    fireEvent.click(await screen.findByRole("button", { name: "Authorize 100 CKB spend" }));

    expect(await screen.findByRole("heading", { name: "Transaction submitted" })).toBeVisible();
    expect(screen.getByLabelText(`Transaction hash ${spendTxHash}`)).toBeVisible();
    expect(operations.submit).toHaveBeenCalledTimes(1);
    finishConfirmation({ ...submittedReceipt, status: "committed" });
    expect(await screen.findByRole("heading", { name: "Spend committed" })).toBeVisible();
  });

  it("rechecks a timed-out hash without submitting another transaction", async () => {
    storePasskey();
    const confirm = vi.fn()
      .mockResolvedValueOnce({ ...submittedReceipt, status: "confirmation_timeout" })
      .mockResolvedValueOnce({ ...submittedReceipt, status: "committed" });
    const operations = spendOperations(confirm);
    render(
      <App
        api={api({ ...status, account }, account)}
        storage={localStorage}
        chainClient={spendClient}
        spendOperations={operations}
        credentials={{} as CredentialsContainer}
      />,
    );

    fireEvent.click(await screen.findByRole("button", { name: "Authorize 100 CKB spend" }));
    fireEvent.click(await screen.findByRole("button", { name: "Check again" }));

    expect(await screen.findByRole("heading", { name: "Spend committed" })).toBeVisible();
    expect(operations.submit).toHaveBeenCalledTimes(1);
    expect(confirm).toHaveBeenCalledTimes(2);
  });

  it("re-fetches authoritative manifests after commitment without hiding the irreversible receipt", async () => {
    storePasskey();
    const integratedApi: DemoApi = {
      status: vi.fn()
        .mockResolvedValueOnce({ ...status, account })
        .mockResolvedValueOnce({ ...status, account: null }),
      account: vi.fn().mockResolvedValue(account),
      bootstrap: vi.fn(),
    };
    render(
      <App
        api={integratedApi}
        storage={localStorage}
        chainClient={spendClient}
        spendOperations={spendOperations()}
        credentials={{} as CredentialsContainer}
      />,
    );

    fireEvent.click(await screen.findByRole("button", { name: "Authorize 100 CKB spend" }));

    expect(await screen.findByRole("heading", { name: "Spend committed" })).toBeVisible();
    expect(screen.getByLabelText(`Transaction hash ${spendTxHash}`)).toBeVisible();
    expect(screen.getByRole("alert")).toHaveTextContent(/server account state changed/i);
    expect(integratedApi.status).toHaveBeenCalledTimes(2);
    expect(integratedApi.account).toHaveBeenCalledTimes(2);
  });
});
