import vectorJson from "../../../vectors/frontend-v1.json";

export interface FrontendVector {
  schema_version: 1;
  inputs: {
    operation: number;
    sequence: string;
    public_key: string;
    origin: string;
    authenticator_data: string;
    client_data_json: string;
    signature: string;
    tx_hash: string;
    account_id: string;
  };
  state: string;
  state_hash: string;
  p256_proof: string;
  account_witness: string;
  packed_witness_args: string;
  group_sighash: string;
  authorization_digest: string;
}

export const frontendVector = vectorJson as FrontendVector;
