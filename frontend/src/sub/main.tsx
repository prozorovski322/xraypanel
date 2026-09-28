import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import { SubscriptionPage } from "@/sub/page";

import "../index.css";

const root = document.getElementById("root");
if (!root) throw new Error("no #root element");

createRoot(root).render(
  <StrictMode>
    <SubscriptionPage />
  </StrictMode>,
);
