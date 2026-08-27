import { useEffect, useRef, useState } from "react";

import type { VerifiedAccount } from "../../shared/manifests.js";
import type { PasskeyRecord, TransactionReceipt } from "../../shared/schemas.js";
import { hexFromBytes } from "../../shared/bytes.js";
import {
  confirmSpend,
  finalizeSpend,
  prepareSpend,
  submitSpend,
  type PreparedSpend,
  type SpendClient,
} from "../chain.js";
import {
  PasskeyCancelledError,
  requestAssertion,
} from "../passkey.js";

export interface SpendStepOperations {
  prepare: typeof prepareSpend;
  requestAssertion: typeof requestAssertion;
  finalize: typeof finalizeSpend;
  submit: typeof submitSpend;
  confirm: typeof confirmSpend;
}

export interface SpendStepProps {
  client: SpendClient;
  account: VerifiedAccount;
  funderAddress: string;
  passkey: PasskeyRecord;
  credentials: CredentialsContainer;
  onReceipt(receipt: TransactionReceipt): void;
  operations?: SpendStepOperations;
}

const defaultOperations: SpendStepOperations = {
  prepare: prepareSpend,
  requestAssertion,
  finalize: finalizeSpend,
  submit: submitSpend,
  confirm: confirmSpend,
};

type SpendState =
  | { kind: "preparing" }
  | { kind: "ready"; prepared: PreparedSpend; notice?: string }
  | { kind: "working"; prepared: PreparedSpend; phase: "authorizing" | "submitting" }
  | { kind: "submitted"; prepared: PreparedSpend }
  | { kind: "blocked"; message: string; prepared?: PreparedSpend };

function formatCkb(shannons: string): string {
  const value = BigInt(shannons);
  const whole = value / 100_000_000n;
  const fraction = (value % 100_000_000n).toString().padStart(8, "0").replace(/0+$/, "");
  return fraction.length === 0 ? `${whole} CKB` : `${whole}.${fraction} CKB`;
}

function dependencyName(name: PreparedSpend["review"]["dependencies"][number]["name"]): string {
  switch (name) {
    case "account_lock":
      return "AccountLock code";
    case "verifier_p256":
      return "P-256 verifier code";
    case "account_state":
      return "AccountState cell";
  }
}

export function SpendStep({
  client,
  account,
  funderAddress,
  passkey,
  credentials,
  onReceipt,
  operations = defaultOperations,
}: SpendStepProps) {
  const [state, setState] = useState<SpendState>({ kind: "preparing" });
  const actionLock = useRef(false);

  useEffect(() => {
    let current = true;
    setState({ kind: "preparing" });
    void operations.prepare({ client, account, funderAddress, passkey })
      .then((prepared) => {
        if (current) setState({ kind: "ready", prepared });
      })
      .catch(() => {
        if (current) {
          setState({
            kind: "blocked",
            message: "The live AccountState and AccountLock asset cells could not be verified for this spend.",
          });
        }
      });
    return () => {
      current = false;
    };
  }, [account, client, funderAddress, operations, passkey]);

  async function authorize(prepared: PreparedSpend): Promise<void> {
    if (actionLock.current || state.kind !== "ready") return;
    actionLock.current = true;
    const reviewedRawHash = prepared.transaction.hash();
    const reviewedDigest = hexFromBytes(prepared.authorizationDigest);
    setState({ kind: "working", prepared, phase: "authorizing" });
    try {
      const assertion = await operations.requestAssertion(
        prepared.authorizationDigest,
        passkey,
        credentials,
      );
      if (
        prepared.transaction.hash() !== reviewedRawHash ||
        hexFromBytes(prepared.authorizationDigest) !== reviewedDigest
      ) {
        setState({
          kind: "blocked",
          prepared,
          message: "The transaction changed while passkey authorization was open. Nothing was submitted.",
        });
        return;
      }
      const finalized = operations.finalize(prepared, passkey, assertion);
      setState({ kind: "working", prepared, phase: "submitting" });
      const submitted = await operations.submit(client, finalized);
      setState({ kind: "submitted", prepared });
      onReceipt(submitted);
      const confirmed = await operations.confirm(client, submitted);
      onReceipt(confirmed);
    } catch (error) {
      if (error instanceof PasskeyCancelledError) {
        setState({
          kind: "ready",
          prepared,
          notice: "Passkey authorization was cancelled. The reviewed transaction is unchanged.",
        });
      } else if (error instanceof TypeError && /credential/i.test(error.message)) {
        setState({
          kind: "blocked",
          prepared,
          message: "The returned credential did not match the reviewed spend. Nothing was submitted.",
        });
      } else {
        setState({
          kind: "blocked",
          prepared,
          message: "The spend outcome could not be completed safely. Reconcile the transaction and live cells before trying again.",
        });
      }
    } finally {
      actionLock.current = false;
    }
  }

  const prepared = "prepared" in state ? state.prepared : undefined;
  const pending = state.kind === "working";

  return (
    <section className="step-card" aria-labelledby="spend-step-heading">
      <p className="step-number">STEP 03 / 03</p>
      <h2 id="spend-step-heading">Authorize your first spend</h2>
      <p className="step-copy">
        Review the exact fixed transfer, fee, change, live input, and code dependencies before your passkey authorizes this transaction.
      </p>

      {state.kind === "preparing" && (
        <p role="status" aria-live="polite" className="inline-status">
          <span className="spinner" aria-hidden="true" />
          Discovering live account cells and preparing the transaction…
        </p>
      )}

      {prepared !== undefined && (
        <>
          <dl className="review-summary">
            <div><dt>Input capacity</dt><dd>{formatCkb(prepared.review.inputCapacityShannons)}</dd></div>
            <div><dt>Transfer to local funder</dt><dd>{formatCkb(prepared.review.transferCapacityShannons)}</dd></div>
            <div><dt>AccountLock change</dt><dd>{formatCkb(prepared.review.changeCapacityShannons)}</dd></div>
            <div><dt>Transaction fee</dt><dd>{formatCkb(prepared.review.feeShannons)}</dd></div>
            <div><dt>Live asset input</dt><dd>{prepared.review.inputOutPoint.txHash}:{prepared.review.inputOutPoint.index}</dd></div>
            <div><dt>Authorization digest</dt><dd>{hexFromBytes(prepared.authorizationDigest)}</dd></div>
          </dl>
          <div className="dependency-summary">
            <h3>Verified dependencies</h3>
            <ol className="dependency-list">
              {prepared.review.dependencies.map((dependency) => (
                <li key={dependency.name}>
                  <span>{dependencyName(dependency.name)}</span>
                  <code>{dependency.txHash}:{dependency.index}</code>
                </li>
              ))}
            </ol>
          </div>
        </>
      )}

      {state.kind === "ready" && state.notice !== undefined && (
        <p role="status" aria-live="polite" className="inline-status">{state.notice}</p>
      )}
      {pending && (
        <p role="status" aria-live="polite" className="inline-status">
          <span className="spinner" aria-hidden="true" />
          {state.phase === "authorizing"
            ? "Waiting for passkey authorization…"
            : "Submitting the authorized transaction exactly once…"}
        </p>
      )}
      {state.kind === "blocked" && (
        <p role="alert" aria-live="assertive" className="inline-error">{state.message}</p>
      )}

      {prepared !== undefined && state.kind !== "submitted" && (
        <button
          type="button"
          className="primary-action"
          disabled={pending || state.kind === "blocked"}
          aria-busy={pending}
          onClick={() => void authorize(prepared)}
        >
          {state.kind === "working"
            ? state.phase === "authorizing" ? "Waiting for passkey" : "Submitting transaction"
            : "Authorize 100 CKB spend"}
        </button>
      )}
      <p className="action-note">The passkey challenge commits to the reviewed transaction. No browser-held CKB private key.</p>
    </section>
  );
}
