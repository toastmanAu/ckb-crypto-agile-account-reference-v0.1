import { useRef, useState } from "react";

import { EXPLORER_URL } from "../../shared/constants.js";
import {
  TransactionReceiptSchema,
  type SubmittedReceipt,
  type TransactionReceipt,
} from "../../shared/schemas.js";
import {
  confirmSpend,
  type SpendClient,
} from "../chain.js";

export interface ReceiptOperations {
  confirm: typeof confirmSpend;
}

export interface ReceiptProps {
  receipt: TransactionReceipt;
  client: SpendClient;
  onReceipt(receipt: TransactionReceipt): void;
  operations?: ReceiptOperations;
  clipboard?: Pick<Clipboard, "writeText">;
  reconciliationError?: string | null;
}

const defaultOperations: ReceiptOperations = { confirm: confirmSpend };

function formatCkb(shannons: string): string {
  const value = BigInt(shannons);
  const whole = value / 100_000_000n;
  const fraction = (value % 100_000_000n).toString().padStart(8, "0").replace(/0+$/, "");
  return fraction.length === 0 ? `${whole} CKB` : `${whole}.${fraction} CKB`;
}

export function Receipt({
  receipt: receiptValue,
  client,
  onReceipt,
  operations = defaultOperations,
  clipboard = globalThis.navigator.clipboard,
  reconciliationError = null,
}: ReceiptProps) {
  const parsed = TransactionReceiptSchema.safeParse(receiptValue);
  const [checking, setChecking] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const checkLock = useRef(false);

  if (!parsed.success) {
    return <p role="alert" className="inline-error">The transaction receipt is malformed.</p>;
  }
  const receipt = parsed.data;
  const expectedExplorerUrl = `${EXPLORER_URL}${receipt.txHash}`;
  if (receipt.explorerUrl !== expectedExplorerUrl) {
    return <p role="alert" className="inline-error">The receipt explorer link does not match the CKB testnet transaction.</p>;
  }

  async function copyHash(): Promise<void> {
    setError(null);
    if (clipboard === undefined) {
      setError("Clipboard access is unavailable. Select the full transaction hash instead.");
      return;
    }
    try {
      await clipboard.writeText(receipt.txHash);
      setNotice("Transaction hash copied.");
    } catch {
      setError("The transaction hash could not be copied. Select the full value instead.");
    }
  }

  async function checkAgain(): Promise<void> {
    if (checkLock.current || receipt.status === "committed") return;
    checkLock.current = true;
    setChecking(true);
    setError(null);
    const submitted: SubmittedReceipt = { ...receipt, status: "submitted" };
    try {
      onReceipt(await operations.confirm(client, submitted));
    } catch {
      setError("The existing transaction could not be checked. No new transaction was sent.");
    } finally {
      checkLock.current = false;
      setChecking(false);
    }
  }

  const committed = receipt.status === "committed";
  const timedOut = receipt.status === "confirmation_timeout";
  const statusMessage = committed
    ? "The spend is committed with a verified live AccountLock change."
    : timedOut
      ? "Confirmation is taking longer than expected. The submitted transaction hash is preserved."
      : "The transaction was submitted once and is waiting for testnet commitment.";

  return (
    <section className={`step-card receipt-card${committed ? " committed-card" : ""}`} aria-labelledby="receipt-heading">
      <p className="step-number">{committed ? "COMMITTED" : "SUBMITTED"}</p>
      <h2 id="receipt-heading">{committed ? "Spend committed" : "Transaction submitted"}</h2>
      <output role="status" aria-live="polite" className="inline-status">
        {statusMessage}{notice === null ? "" : ` ${notice}`}
      </output>

      <div className="hash-panel">
        <p>Transaction hash</p>
        <code aria-label={`Transaction hash ${receipt.txHash}`}>{receipt.txHash}</code>
        <button type="button" className="tertiary-action" onClick={() => void copyHash()}>
          Copy transaction hash
        </button>
      </div>

      {committed && (
        <dl className="review-summary">
          <div>
            <dt>Verified AccountLock change</dt>
            <dd>{formatCkb(receipt.remainingCapacityShannons)}</dd>
          </div>
        </dl>
      )}
      {error !== null && <p role="alert" className="inline-error">{error}</p>}
      {reconciliationError !== null && (
        <p role="alert" aria-live="assertive" className="inline-error">
          {reconciliationError}
        </p>
      )}

      <div className="receipt-actions">
        <a className="secondary-action" href={receipt.explorerUrl} target="_blank" rel="noreferrer">
          View transaction in explorer
        </a>
        {!committed && (
          <button
            type="button"
            className="tertiary-action"
            disabled={checking}
            aria-busy={checking}
            onClick={() => void checkAgain()}
          >
            {checking ? "Checking transaction" : "Check again"}
          </button>
        )}
      </div>
    </section>
  );
}
