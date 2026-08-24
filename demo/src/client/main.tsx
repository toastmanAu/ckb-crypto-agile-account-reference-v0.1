import { ccc } from "@ckb-ccc/core";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import { App } from "./App.js";
import { createDemoApi } from "./api.js";
import "./styles.css";

const root = document.getElementById("root");
if (root === null) {
  throw new Error("Application root is missing");
}
const fixtureRpcUrl = import.meta.env.VITE_CKB_RPC_URL as string | undefined;
const chainClient = new ccc.ClientPublicTestnet(
  fixtureRpcUrl === undefined ? undefined : { url: fixtureRpcUrl, fallbacks: [] },
);

createRoot(root).render(
  <StrictMode>
    <App api={createDemoApi()} storage={window.localStorage} chainClient={chainClient} />
  </StrictMode>,
);
