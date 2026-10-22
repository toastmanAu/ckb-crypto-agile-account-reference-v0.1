import { useRef, useState } from "react";

import {
  PasskeyRecordSchema,
  type PasskeyRecord,
} from "../../shared/schemas.js";
import {
  PasskeyCancelledError,
  PasskeyProtocolError,
  passkeyCapabilityProblem,
  registerPasskey,
} from "../passkey.js";
import { savePasskeyRecord } from "../storage.js";

type RegisterPasskey = typeof registerPasskey;

export interface PasskeyStepProps {
  storage: Storage;
  credentials: CredentialsContainer;
  cryptoProvider: Crypto;
  onCreated(record: PasskeyRecord): void;
  register?: RegisterPasskey;
}

type StepState =
  | { kind: "ready" }
  | { kind: "pending" }
  | { kind: "cancelled" }
  | { kind: "success"; record: PasskeyRecord }
  | { kind: "blocked"; message: string };

export function PasskeyStep({
  storage,
  credentials,
  cryptoProvider,
  onCreated,
  register = registerPasskey,
}: PasskeyStepProps) {
  const [state, setState] = useState<StepState>({ kind: "ready" });
  const actionLock = useRef(false);
  const capabilityProblem = passkeyCapabilityProblem();

  async function createPasskey(): Promise<void> {
    if (actionLock.current || capabilityProblem !== null || state.kind === "blocked") return;
    actionLock.current = true;
    setState({ kind: "pending" });
    try {
      const candidate = await register(credentials, cryptoProvider);
      const result = PasskeyRecordSchema.safeParse(candidate);
      if (!result.success) {
        setState({
          kind: "blocked",
          message: "The browser did not return valid public metadata for this passkey.",
        });
        return;
      }
      savePasskeyRecord(storage, result.data);
      setState({ kind: "success", record: result.data });
      onCreated(result.data);
    } catch (error) {
      if (error instanceof PasskeyCancelledError) {
        setState({ kind: "cancelled" });
      } else if (error instanceof PasskeyProtocolError) {
        setState({
          kind: "blocked",
          message: "The browser returned an incompatible passkey response. Use current Chromium on secure localhost.",
        });
      } else {
        setState({
          kind: "blocked",
          message: "The passkey public metadata could not be validated or saved.",
        });
      }
    } finally {
      actionLock.current = false;
    }
  }

  const pending = state.kind === "pending";
  const blocked = state.kind === "blocked";

  return (
    <section className="step-card" aria-labelledby="passkey-step-heading">
      <p className="step-number">STEP 01 / 03</p>
      <h2 id="passkey-step-heading">Create your passkey</h2>
      <p className="step-copy">
        Create a device-bound P-256 credential. Only its public key and credential ID stay in this browser.
        The browser does not expose the passkey private key.
      </p>

      {capabilityProblem !== null && (
        <p role="alert" aria-live="assertive" className="inline-error">
          {capabilityProblem}
        </p>
      )}
      {state.kind === "cancelled" && (
        <p role="status" aria-live="polite" className="inline-status">
          Passkey creation was cancelled. You can try again when ready.
        </p>
      )}
      {pending && (
        <p role="status" aria-live="polite" className="inline-status">
          <span className="spinner" aria-hidden="true" />
          Waiting for your browser to create the passkey…
        </p>
      )}
      {blocked && (
        <p role="alert" aria-live="assertive" className="inline-error">
          {state.message}
        </p>
      )}
      {state.kind === "success" && (
        <>
          <p role="status" aria-live="polite" className="inline-status">
            Passkey public metadata is saved in this browser.
          </p>
          <dl className="key-summary">
            <div>
              <dt>Passkey public key</dt>
              <dd>{state.record.publicKey}</dd>
            </div>
            <div>
              <dt>Passkey key ID</dt>
              <dd>{state.record.keyId}</dd>
            </div>
          </dl>
        </>
      )}

      {capabilityProblem === null && state.kind !== "success" && (
        <button
          type="button"
          className="primary-action"
          disabled={pending || blocked}
          aria-busy={pending}
          onClick={() => void createPasskey()}
        >
          {pending ? "Creating passkey" : "Create passkey"}
        </button>
      )}
      <p className="action-note">No mainnet funds. No browser-held CKB private key.</p>
    </section>
  );
}
