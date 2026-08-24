export const CLIENT_ORIGIN = "http://localhost:5173";
export const RP_ID = "localhost";
export const API_PORT = 8790 as const;
export const API_ORIGIN = `http://127.0.0.1:${API_PORT}`;

export const SHANNONS_PER_CKB = 100_000_000n;
export const INITIAL_ASSET = 200n * SHANNONS_PER_CKB;
export const TRANSFER_CAPACITY = 100n * SHANNONS_PER_CKB;
export const FEE_RATE = 1_000n;
export const OP_SPEND = 1 as const;

export const EXPLORER_URL = "https://pudge.explorer.nervos.org/transaction/";
