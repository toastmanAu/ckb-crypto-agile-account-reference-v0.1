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
import { StatusHeader } from "./components/StatusHeader.js";
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
  onPrimaryAction?: (stage: ActionableState["stage"]) => Promise<void> | void;
}

function passkeyCapabilityProblem(): string | null {
  if (globalThis.isSecureContext !== true) {
    return "Passkeys need a secure localhost context and Chromium with WebAuthn support.";
  }
  if (typeof globalThis.PublicKeyCredential !== "function") {
    return "This browser does not provide the PublicKeyCredential API required by the demo.";
  }
  if (
    typeof globalThis.AuthenticatorAttestationResponse !== "function" ||
    typeof globalThis.AuthenticatorAttestationResponse.prototype.getPublicKey !== "function"
  ) {
    return "Chromium cannot export the passkey public key required by this AccountLock demo.";
  }
  return null;
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

const stepContent = {
  "needs-passkey": {
    number: "01",
    heading: "Create your passkey",
    body: "Create a device-bound P-256 credential. Only its public key and credential ID stay in this browser.",
    action: "Create passkey",
  },
  "needs-account": {
    number: "02",
    heading: "Create your testnet account",
    body: "Use the local funder to publish one AccountState cell and a 200 CKB AccountLock asset for this passkey.",
    action: "Create testnet account",
  },
  "ready-to-spend": {
    number: "03",
    heading: "Authorize your first spend",
    body: "Review a fixed 100 CKB transfer back to the funder, then authorize the exact transaction with your passkey.",
    action: "Authorize 100 CKB spend",
  },
} as const;

export function App({ api, storage, receipt, onPrimaryAction }: AppProps) {
  const [state, setState] = useState<WizardState>({ stage: "loading" });
  const [actionPending, setActionPending] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  const actionLock = useRef(false);

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

  const displayedState = useMemo(() => withReceipt(state, receipt), [state, receipt]);

  async function runPrimaryAction(stage: ActionableState["stage"]): Promise<void> {
    if (actionLock.current) return;
    actionLock.current = true;
    setActionPending(true);
    setActionError(null);
    try {
      await onPrimaryAction?.(stage);
    } catch {
      setActionError("The action could not be completed. Review the local service and try again.");
    } finally {
      actionLock.current = false;
      setActionPending(false);
    }
  }

  const visibleStatus = "status" in displayedState ? displayedState.status : undefined;

  return (
    <div className="app-shell">
      <StatusHeader status={visibleStatus} />
      <main className="wizard" aria-label="Passkey account setup">
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

        {(displayedState.stage === "needs-passkey" ||
          displayedState.stage === "needs-account" ||
          displayedState.stage === "ready-to-spend") && (() => {
          const content = stepContent[displayedState.stage];
          return (
            <section className="step-card" aria-labelledby="active-step-heading">
              <p className="step-number">STEP {content.number} / 03</p>
              <h2 id="active-step-heading">{content.heading}</h2>
              <p className="step-copy">{content.body}</p>
              {displayedState.passkey !== null && (
                <dl className="key-summary">
                  <div>
                    <dt>Passkey key ID</dt>
                    <dd>{displayedState.passkey.keyId}</dd>
                  </div>
                </dl>
              )}
              {actionError !== null && <p role="alert" className="inline-error">{actionError}</p>}
              <button
                type="button"
                className="primary-action"
                disabled={actionPending}
                onClick={() => void runPrimaryAction(displayedState.stage)}
              >
                {actionPending ? "Working…" : content.action}
              </button>
              <p className="action-note">No mainnet funds. No browser-held CKB private key.</p>
            </section>
          );
        })()}

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

        {displayedState.stage === "submitted" && (
          <section className="step-card receipt-card" aria-labelledby="submitted-heading">
            <p className="step-number">SUBMITTED</p>
            <h2 id="submitted-heading">Transaction submitted</h2>
            <p role="status" aria-live="polite" className="inline-status">
              {displayedState.receipt.status === "confirmation_timeout"
                ? "Confirmation is taking longer than expected. The transaction hash is preserved and the demo will not resubmit."
                : "The transaction is in the CKB testnet pool and is waiting for commitment."}
            </p>
            <a className="secondary-action" href={displayedState.receipt.explorerUrl} target="_blank" rel="noreferrer">
              View transaction in explorer
            </a>
          </section>
        )}

        {displayedState.stage === "committed" && (
          <section className="step-card receipt-card" aria-labelledby="committed-heading">
            <p className="step-number">COMMITTED</p>
            <h2 id="committed-heading">Spend committed</h2>
            <p role="status" aria-live="polite" className="inline-status">
              The 100 CKB spend is committed and the remaining AccountLock change was verified live.
            </p>
            <a className="secondary-action" href={displayedState.receipt.explorerUrl} target="_blank" rel="noreferrer">
              View committed transaction
            </a>
          </section>
        )}
      </main>
      <footer>
        <p>Reference implementation · Local browser ceremony · CKB testnet only</p>
      </footer>
    </div>
  );
}
