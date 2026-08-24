import { API_PORT, CLIENT_ORIGIN, RP_ID } from "../shared/constants.js";
import { ApiError } from "./errors.js";

export interface ServerConfig {
  readonly host: "127.0.0.1";
  readonly port: typeof API_PORT;
  readonly clientOrigin: typeof CLIENT_ORIGIN;
  readonly rpId: typeof RP_ID;
  readonly network: "testnet";
  readonly privateKey: string;
}

export function loadServerConfig(env: NodeJS.ProcessEnv): ServerConfig {
  const privateKey = env.CKB_PRIVKEY ?? "";
  if (!/^0x[0-9a-fA-F]{64}$/.test(privateKey)) {
    throw new ApiError("KEY_UNAVAILABLE", 500, "CKB_PRIVKEY is missing or invalid");
  }

  const config = {
    host: "127.0.0.1",
    port: API_PORT,
    clientOrigin: CLIENT_ORIGIN,
    rpId: RP_ID,
    network: "testnet",
  } as ServerConfig;
  Object.defineProperty(config, "privateKey", {
    value: privateKey,
    enumerable: false,
    configurable: false,
    writable: false,
  });
  return Object.freeze(config);
}
