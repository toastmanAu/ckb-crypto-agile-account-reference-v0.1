import { useRef, useState } from "react";

import { validateAccount, validateDeployment } from "../../shared/manifests.js";
import { EXPLORER_URL } from "../../shared/constants.js";
import type {
  AccountManifest,
  DemoStatus,
  PasskeyRecord,
} from "../../shared/schemas.js";
import { DemoApiError, type DemoApi } from "../api.js";

export interface BootstrapStepProps {
  api: DemoApi;
  status: DemoStatus;
  passkey: PasskeyRecord;
  onCreated(account: AccountManifest): void;
}

type StepState =
  | { kind: "ready" }
  | { kind: "pending" }
  | { kind: "success"; account: AccountManifest }
  | { kind: "error"; message: string; blocking: boolean };

function safeBootstrapError(error: unknown): { message: string; blocking: boolean } {
  if (!(error instanceof DemoApiError)) {
    return {
      message: "The account request outcome is unknown. Restart the local demo to reconcile account state before taking another action.",
      blocking: true,
    };
  }
  switch (error.code) {
    case "INSUFFICIENT_BALANCE":
      return {
        message: "The local funder does not have enough CKB for the account cells and transaction fee. Fund it, then try again.",
        blocking: false,
      };
    case "BOOTSTRAP_FAILED":
      return {
        message: "Account creation may have failed before or after submission. Restart the local demo and inspect account state before taking another action.",
        blocking: true,
      };
    case "ACCOUNT_MISMATCH":
      return {
        message: "The existing account does not match this passkey. Use the browser profile that created it and inspect the account manifest.",
        blocking: true,
      };
    case "CONFIRMATION_TIMEOUT":
      return {
        message: "Account creation may have been submitted, but commitment was not confirmed. Restart the local demo to reconcile the account before taking another action.",
        blocking: true,
      };
    case "DEPLOYMENT_INVALID":
    case "KEY_UNAVAILABLE":
    case "INVALID_RESPONSE":
      return {
        message: "The local account setup is incompatible or incomplete. Inspect the deployment and localhost service before continuing.",
        blocking: true,
      };
    case "API_UNAVAILABLE":
      return {
        message: "The account request outcome is unknown. Restart the local demo to reconcile account state before taking another action.",
        blocking: true,
      };
    default:
      return {
        message: "The account request outcome could not be verified. Restart the local demo and inspect account state before continuing.",
        blocking: true,
      };
  }
}

export function BootstrapStep({ api, status, passkey, onCreated }: BootstrapStepProps) {
  const [state, setState] = useState<StepState>({ kind: "ready" });
  const actionLock = useRef(false);

  async function createAccount(): Promise<void> {
    if (actionLock.current || (state.kind === "error" && state.blocking)) return;
    actionLock.current = true;
    setState({ kind: "pending" });
    try {
      const candidate = await api.bootstrap({
        credentialId: passkey.credentialId,
        publicKey: passkey.publicKey,
      });
      const deployment = validateDeployment(status.deployment);
      const account = validateAccount(candidate, deployment).manifest;
      setState({ kind: "success", account });
      onCreated(account);
    } catch (error) {
      setState({ kind: "error", ...safeBootstrapError(error) });
    } finally {
      actionLock.current = false;
    }
  }

  const pending = state.kind === "pending";
  const blocking = state.kind === "error" && state.blocking;

  return (
    <section className="step-card" aria-labelledby="bootstrap-step-heading">
      <p className="step-number">STEP 02 / 03</p>
      <h2 id="bootstrap-step-heading">Create your testnet account</h2>
      <p className="step-copy">
        The localhost funder will publish one AccountState cell and one 200 CKB AccountLock asset for this passkey.
      </p>

      <dl className="review-summary">
        <div>
          <dt>Passkey public key</dt>
          <dd>{passkey.publicKey}</dd>
        </div>
        <div>
          <dt>Passkey key ID</dt>
          <dd>{passkey.keyId}</dd>
        </div>
        <div>
          <dt>Account asset</dt>
          <dd>200 CKB</dd>
        </div>
        <div>
          <dt>Local funder</dt>
          <dd>{status.funderAddress}</dd>
        </div>
        <div>
          <dt>AccountLock data hash</dt>
          <dd>{status.deployment.artifacts.account_lock.dataHash}</dd>
        </div>
        <div>
          <dt>P-256 verifier data hash</dt>
          <dd>{status.deployment.artifacts.verifier_p256.dataHash}</dd>
        </div>
      </dl>

      {pending && (
        <p role="status" aria-live="polite" className="inline-status">
          <span className="spinner" aria-hidden="true" />
          Submitting account creation and waiting for testnet commitment…
        </p>
      )}
      {state.kind === "error" && (
        <p role="alert" aria-live={state.blocking ? "assertive" : "polite"} className="inline-error">
          {state.message}
        </p>
      )}
      {state.kind === "success" && (
        <>
          <p role="status" aria-live="polite" className="inline-status">
            Account creation is committed. Rechecking authoritative account state…
          </p>
          <a
            className="secondary-action"
            href={`${EXPLORER_URL}${state.account.state_out_point.tx_hash}`}
            target="_blank"
            rel="noreferrer"
          >
            View account creation in explorer
          </a>
        </>
      )}

      {state.kind !== "success" && (
        <button
          type="button"
          className="primary-action"
          disabled={pending || blocking}
          aria-busy={pending}
          onClick={() => void createAccount()}
        >
          {pending ? "Creating testnet account" : "Create testnet account"}
        </button>
      )}
      <p className="action-note">The browser sends only the credential ID and public key to localhost.</p>
    </section>
  );
}
