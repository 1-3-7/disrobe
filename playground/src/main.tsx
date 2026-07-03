import React from "react";
import { createRoot } from "react-dom/client";
import App from "@/App";
import { initFavicon } from "@/lib/theme";
import "@/styles.css";

const root: HTMLElement | null = document.getElementById("root");

if (root === null) {
  throw new Error("playground root element is missing");
}

initFavicon();

createRoot(root).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
