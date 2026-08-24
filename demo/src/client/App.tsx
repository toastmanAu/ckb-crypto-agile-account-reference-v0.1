import { useEffect, useMemo, useRef, useState } from "react";

import { validateAccount, validateDeployment } from "../shared/manifests.js";
import {
  TransactionReceiptSchema,
  type AccountManifest,
  type DemoStatus,
  type PasskeyRecord,
  type TransactionReceipt,
} from "../shared/schemas.js";
import type { DemoApi } from "./api.js";
import { DemoApiError } from "./api.js";
import type { SpendClient } from "./chain.js";
import { BootstrapStep } from "./components/BootstrapStep.js";
import { PasskeyStep } from "./components/PasskeyStep.js";
import { Receipt } from "./components/Receipt.js";
import { SpendStep, type SpendStepOperations } from "./components/SpendStep.js";
import { StatusHeader } from "./components/StatusHeader.js";
import { passkeyCapabilityProblem, registerPasskey } from "./passkey.js";
import { loadPasskeyRecord } from "./storage.js";

export type WizardStage =
  | "loading"
  | "needs-passkey"
  | "needs-account"
  | "ready-to-spend"
  | "submitted"
  | "committed"
  | "blocked";

interface LoadingState {
  stage: "loading";
}

interface ActionableState {
  stage: "needs-passkey" | "needs-account" | "ready-to-spend";
  status: DemoStatus;
  account: AccountManifest | null;
  passkey: PasskeyRecord | null;
}

interface ReceiptState {
  stage: "submitted" | "committed";
  status: DemoStatus;
  receipt: TransactionReceipt;
}

interface BlockedState {
  stage: "blocked";
  status?: DemoStatus;
  heading: string;
  message: string;
}

type WizardState = LoadingState | ActionableState | ReceiptState | BlockedState;

export interface AppProps {
  api: DemoApi;
  storage: Storage;
  receipt?: TransactionReceipt | null;
  credentials?: CredentialsContainer;
  cryptoProvider?: Crypto;
  register?: typeof registerPasskey;
  chainClient?: SpendClient;
  spendOperations?: SpendStepOperations;
  clipboard?: Pick<Clipboard, "writeText">;
}

function sameAccount(
  statusAccount: AccountManifest | null,
  account: AccountManifest | null,
): boolean {
  return JSON.stringify(statusAccount) === JSON.stringify(account);
}

function reconcile(
  status: DemoStatus,
  account: AccountManifest | null,
  passkey: PasskeyRecord | null,
): WizardState {
  if (!status.deploymentVerified) {
    return {
      stage: "blocked",
      status,
      heading: "Local setup is blocked",
      message: "The published AccountLock deployment has not been verified.",
    };
  }
  try {
    const deployment = validateDeployment(status.deployment);
    if (status.account !== null) validateAccount(status.account, deployment);
    if (account !== null) validateAccount(account, deployment);
  } catch {
    return {
      stage: "blocked",
      status,
      heading: "Local setup is blocked",
      message: "The server returned account data that does not match the verified deployment.",
    };
  }
  if (!sameAccount(status.account, account)) {
    return {
      stage: "blocked",
      status,
      heading: "Account access is blocked",
      message: "The server account state changed between checks. Restart the local demo and inspect the account manifest before continuing.",
    };
  }

  const capabilityProblem = passkeyCapabilityProblem();
  if (capabilityProblem !== null) {
    return {
      stage: "blocked",
      status,
      heading: "Passkeys are unavailable",
      message: capabilityProblem,
    };
  }
  if (account !== null && passkey === null) {
    return {
      stage: "blocked",
      status,
      heading: "Account access is blocked",
      message: "An account exists on testnet, but local passkey metadata is missing. Use the browser profile that created this account; do not create a replacement.",
    };
  }
  if (passkey === null) {
    return { stage: "needs-passkey", status, account: null, passkey: null };
  }
  if (account === null) {
    return { stage: "needs-account", status, account: null, passkey };
  }
  return { stage: "ready-to-spend", status, account, passkey };
}

function withReceipt(state: WizardState, receiptValue: TransactionReceipt | null | undefined): WizardState {
  if (receiptValue == null) return state;
  if (state.stage === "loading" || state.stage === "blocked") return state;
  if (state.stage !== "ready-to-spend") {
    return {
      stage: "blocked",
      status: "status" in state ? state.status : undefined,
      heading: "Receipt cannot be reconciled",
      message: "The transaction receipt does not match the current local account state.",
    };
  }
  const result = TransactionReceiptSchema.safeParse(receiptValue);
  if (!result.success) {
    return {
      stage: "blocked",
      status: state.status,
      heading: "Receipt cannot be reconciled",
      message: "The stored transaction receipt is malformed.",
    };
  }
  return {
    stage: result.data.status === "committed" ? "committed" : "submitted",
    status: state.status,
    receipt: result.data,
  };
}

export function App({
  api,
  storage,
  receipt,
  credentials = globalThis.navigator.credentials,
  cryptoProvider = globalThis.crypto,
  register = registerPasskey,
  chainClient,
  spendOperations,
  clipboard,
}: AppProps) {
  const [state, setState] = useState<WizardState>({ stage: "loading" });
  const [internalReceipt, setInternalReceipt] = useState<TransactionReceipt | null>(null);
  const [postCommitError, setPostCommitError] = useState<string | null>(null);
  const wizardRef = useRef<HTMLElement>(null);
  const reconciledCommit = useRef<string | null>(null);

  useEffect(() => {
    let current = true;
    const passkey = loadPasskeyRecord(storage);
    void Promise.all([api.status(), api.account()])
      .then(([status, account]) => {
        if (current) setState(reconcile(status, account, passkey));
      })
      .catch((error: unknown) => {
        if (!current) return;
        setState({
          stage: "blocked",
          heading: "Local setup is blocked",
          message: error instanceof DemoApiError ? error.message : "Local API is unavailable",
        });
      });
    return () => {
      current = false;
    };
  }, [api, storage]);

  const displayedState = useMemo(
    () => withReceipt(state, internalReceipt ?? receipt),
    [internalReceipt, receipt, state],
  );

  useEffect(() => {
    const heading = wizardRef.current?.querySelector<HTMLElement>("h2");
    if (heading === undefined || heading === null) return;
    heading.tabIndex = -1;
    heading.focus();
  }, [displayedState.stage]);

  function handlePasskeyCreated(passkey: PasskeyRecord): void {
    if (state.stage !== "needs-passkey") return;
    setState(reconcile(state.status, state.account, passkey));
  }

  function handleAccountCreated(): void {
    if (state.stage !== "needs-account" || state.passkey === null) return;
    const passkey = state.passkey;
    void Promise.all([api.status(), api.account()])
      .then(([status, account]) => {
        setState(reconcile(status, account, passkey));
      })
      .catch((error: unknown) => {
        setState({
          stage: "blocked",
          heading: "Local setup is blocked",
          message: error instanceof DemoApiError ? error.message : "Local API is unavailable",
        });
      });
  }

  function handleSpendReceipt(receiptValue: TransactionReceipt): void {
    const result = TransactionReceiptSchema.safeParse(receiptValue);
    if (!result.success) {
      setState({
        stage: "blocked",
        heading: "Receipt cannot be reconciled",
        message: "The transaction receipt is malformed.",
      });
      return;
    }
    const nextReceipt = result.data;
    setInternalReceipt(nextReceipt);
    if (
      nextReceipt.status !== "committed" ||
      reconciledCommit.current === nextReceipt.txHash ||
      state.stage !== "ready-to-spend" ||
      state.passkey === null
    ) {
      return;
    }
    reconciledCommit.current = nextReceipt.txHash;
    setPostCommitError(null);
    const passkey = state.passkey;
    void Promise.all([api.status(), api.account()])
      .then(([status, account]) => {
        const reconciled = reconcile(status, account, passkey);
        if (reconciled.stage === "blocked") {
          setPostCommitError(reconciled.message);
        } else {
          setState(reconciled);
        }
      })
      .catch(() => {
        setPostCommitError(
          "The committed transaction is preserved, but authoritative account state could not be refreshed.",
        );
      });
  }

  const visibleStatus = "status" in displayedState ? displayedState.status : undefined;

  return (
    <div className="app-shell">
      <StatusHeader status={visibleStatus} />
      <main ref={wizardRef} className="wizard" aria-label="Passkey account setup">
        {displayedState.stage === "loading" && (
          <section className="step-card" aria-labelledby="loading-heading">
            <p className="step-number">LOCAL CHECK</p>
            <h2 id="loading-heading">Preparing your account</h2>
            <p className="step-copy">Validating the local API, deployment, browser storage, and account manifest.</p>
            <p className="inline-status" role="status" aria-live="polite">
              <span className="spinner" aria-hidden="true" />
              Checking local services…
            </p>
          </section>
        )}

        {displayedState.stage === "needs-passkey" && (
          <PasskeyStep
            storage={storage}
            credentials={credentials}
            cryptoProvider={cryptoProvider}
            register={register}
            onCreated={handlePasskeyCreated}
          />
        )}

        {displayedState.stage === "needs-account" && displayedState.passkey !== null && (
          <BootstrapStep
            api={api}
            status={displayedState.status}
            passkey={displayedState.passkey}
            onCreated={handleAccountCreated}
          />
        )}

        {displayedState.stage === "ready-to-spend" &&
          displayedState.account !== null &&
          displayedState.passkey !== null &&
          chainClient !== undefined && (
            <SpendStep
              client={chainClient}
              account={validateAccount(
                displayedState.account,
                validateDeployment(displayedState.status.deployment),
              )}
              funderAddress={displayedState.status.funderAddress}
              passkey={displayedState.passkey}
              credentials={credentials}
              operations={spendOperations}
              onReceipt={handleSpendReceipt}
            />
          )}

        {displayedState.stage === "ready-to-spend" && chainClient === undefined && (
          <section className="step-card blocked-card" aria-labelledby="chain-client-heading">
            <p className="step-number">ACTION REQUIRED</p>
            <h2 id="chain-client-heading">Public testnet access is unavailable</h2>
            <p role="alert" className="inline-error">The browser chain client is not configured.</p>
          </section>
        )}

        {displayedState.stage === "blocked" && (
          <section className="step-card blocked-card" aria-labelledby="blocked-heading">
            <p className="step-number">ACTION REQUIRED</p>
            <h2 id="blocked-heading">{displayedState.heading}</h2>
            <p role="alert" aria-live="assertive" className="inline-error">
              {displayedState.message}
            </p>
            <p className="step-copy">This demo fails closed so it cannot strand capacity or authorize with the wrong credential.</p>
          </section>
        )}

        {(displayedState.stage === "submitted" || displayedState.stage === "committed") &&
          chainClient !== undefined && (
            <Receipt
              receipt={displayedState.receipt}
              client={chainClient}
              operations={spendOperations === undefined ? undefined : { confirm: spendOperations.confirm }}
              clipboard={clipboard}
              reconciliationError={postCommitError}
              onReceipt={handleSpendReceipt}
            />
          )}
      </main>
      <footer>
        <p>Reference implementation · Local browser ceremony · CKB testnet only</p>
      </footer>
    </div>
  );
}
