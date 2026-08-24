import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import { App } from "./App.js";
import { createDemoApi } from "./api.js";
import "./styles.css";

const root = document.getElementById("root");
if (root === null) {
  throw new Error("Application root is missing");
}

createRoot(root).render(
  <StrictMode>
    <App api={createDemoApi()} storage={window.localStorage} />
  </StrictMode>,
);
