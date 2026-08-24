import type { DemoStatus } from "../../shared/schemas.js";

const SHANNONS_PER_CKB = 100_000_000n;

function groupedDecimal(value: bigint): string {
  return value.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
}

export function formatCkbBalance(shannons: string): string {
  const value = BigInt(shannons);
  const whole = value / SHANNONS_PER_CKB;
  const fraction = (value % SHANNONS_PER_CKB)
    .toString()
    .padStart(8, "0")
    .replace(/0+$/, "");
  return `${groupedDecimal(whole)}${fraction === "" ? "" : `.${fraction}`} CKB`;
}

export interface StatusHeaderProps {
  status?: DemoStatus;
}

export function StatusHeader({ status }: StatusHeaderProps) {
  return (
    <header className="status-header">
      <div className="brand-row">
        <div>
          <p className="brand-kicker">CKB / PASSKEY</p>
          <h1>Crypto-agile account</h1>
        </div>
        <span className="network-indicator" aria-label="CKB testnet connection">
          <span className="network-dot" aria-hidden="true" />
          Testnet
        </span>
      </div>

      <ul className="safety-labels" aria-label="Demo safety labels">
        <li>CKB testnet</li>
        <li>localhost</li>
        <li>Unaudited reference</li>
      </ul>

      <section className="service-summary" aria-label="Local service status">
        {status === undefined ? (
          <p className="service-pending">Waiting for the local API and deployment status.</p>
        ) : (
          <dl>
            <div className="summary-item summary-address">
              <dt>Backend funder</dt>
              <dd>{status.funderAddress}</dd>
            </div>
            <div className="summary-item">
              <dt>Public balance</dt>
              <dd>{formatCkbBalance(status.funderBalanceShannons)}</dd>
            </div>
            <div className="summary-item">
              <dt>Deployment</dt>
              <dd>{status.deploymentVerified ? "Code cells verified" : "Verification required"}</dd>
            </div>
          </dl>
        )}
      </section>
    </header>
  );
}
