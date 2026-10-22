import "@testing-library/jest-dom/vitest";

import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { Receipt, type ReceiptOperations } from "../../src/client/components/Receipt.js";
import type { SpendClient } from "../../src/client/chain.js";
import { EXPLORER_URL } from "../../src/shared/constants.js";
import type {
  CommittedReceipt,
  ConfirmationTimedOutReceipt,
  SubmittedReceipt,
  TransactionReceipt,
} from "../../src/shared/schemas.js";

const txHash = `0x${"aa".repeat(32)}` as const;
const submitted: SubmittedReceipt = {
  status: "submitted",
  txHash,
  explorerUrl: `${EXPLORER_URL}${txHash}`,
  remainingCapacityShannons: "9999900000",
};
const committed: CommittedReceipt = { ...submitted, status: "committed" };
const timeout: ConfirmationTimedOutReceipt = { ...submitted, status: "confirmation_timeout" };

function renderReceipt(
  receipt: TransactionReceipt,
  operations: ReceiptOperations = { confirm: vi.fn() },
  onReceipt = vi.fn(),
  clipboard = { writeText: vi.fn().mockResolvedValue(undefined) },
) {
  return {
    clipboard,
    onReceipt,
    ...render(
      <Receipt
        receipt={receipt}
        client={{} as SpendClient}
        operations={operations}
        clipboard={clipboard}
        onReceipt={onReceipt}
      />,
    ),
  };
}

describe("Receipt", () => {
  afterEach(cleanup);

  it("shows the full hash and testnet explorer link immediately after submission", () => {
    renderReceipt(submitted);

    expect(screen.getByRole("heading", { name: "Transaction submitted" })).toBeVisible();
    expect(screen.getByLabelText(`Transaction hash ${txHash}`)).toHaveTextContent(txHash);
    expect(screen.getByRole("link", { name: /view transaction/i })).toHaveAttribute(
      "href",
      `${EXPLORER_URL}${txHash}`,
    );
    expect(screen.queryByText("99.999 CKB")).not.toBeInTheDocument();
  });

  it("makes the full transaction hash copyable and announces success", async () => {
    const { clipboard } = renderReceipt(submitted);

    fireEvent.click(screen.getByRole("button", { name: "Copy transaction hash" }));

    await waitFor(() => expect(clipboard.writeText).toHaveBeenCalledWith(txHash));
    expect(screen.getByRole("status")).toHaveTextContent(/transaction hash copied/i);
  });

  it("renders commitment distinctly and reveals rescanned remaining capacity", () => {
    renderReceipt(committed);

    expect(screen.getByRole("heading", { name: "Spend committed" })).toBeVisible();
    expect(screen.getByText("99.999 CKB")).toBeVisible();
    expect(screen.getByText(/verified live AccountLock change/i)).toBeVisible();
  });

  it("preserves timeout as submitted and checks the same hash without broadcasting", async () => {
    const confirm = vi.fn().mockResolvedValue(committed);
    const onReceipt = vi.fn();
    renderReceipt(timeout, { confirm }, onReceipt);

    expect(screen.getByRole("heading", { name: "Transaction submitted" })).toBeVisible();
    expect(screen.getByRole("status")).toHaveTextContent(/taking longer than expected/i);
    fireEvent.click(screen.getByRole("button", { name: "Check again" }));

    await waitFor(() => expect(onReceipt).toHaveBeenCalledWith(committed));
    expect(confirm).toHaveBeenCalledTimes(1);
    expect(confirm).toHaveBeenCalledWith(
      expect.anything(),
      { ...timeout, status: "submitted" },
    );
    expect(screen.queryByText(/resubmit/i)).not.toBeInTheDocument();
  });

  it("can recheck an existing submitted hash if the automatic watcher stops", async () => {
    const confirm = vi.fn().mockResolvedValue(timeout);
    const onReceipt = vi.fn();
    renderReceipt(submitted, { confirm }, onReceipt);

    fireEvent.click(screen.getByRole("button", { name: "Check again" }));

    await waitFor(() => expect(onReceipt).toHaveBeenCalledWith(timeout));
    expect(confirm).toHaveBeenCalledWith(expect.anything(), submitted);
  });

  it("keeps timeout state when a recheck still has not committed", async () => {
    const confirm = vi.fn().mockResolvedValue(timeout);
    const onReceipt = vi.fn();
    renderReceipt(timeout, { confirm }, onReceipt);

    fireEvent.click(screen.getByRole("button", { name: "Check again" }));

    await waitFor(() => expect(onReceipt).toHaveBeenCalledWith(timeout));
    expect(screen.getByRole("button", { name: "Check again" })).toBeEnabled();
  });

  it("fails closed when a receipt tries to navigate away from the testnet explorer", () => {
    renderReceipt({ ...submitted, explorerUrl: `https://evil.example/${txHash}` });

    expect(screen.getByRole("alert")).toHaveTextContent(/explorer link does not match/i);
    expect(screen.queryByRole("link")).not.toBeInTheDocument();
  });
});
