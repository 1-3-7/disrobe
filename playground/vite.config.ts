import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import { fileURLToPath, URL } from "node:url";

const base: string = process.env["PLAYGROUND_BASE"] ?? "/";

export default defineConfig({
  base,
  plugins: [
    react({
      babel: {
        plugins: [["babel-plugin-react-compiler", {}]],
      },
    }),
    tailwindcss(),
  ],
  resolve: {
    alias: {
      "@": fileURLToPath(new URL("./src", import.meta.url)),
    },
  },
  worker: {
    format: "es",
  },
  build: {
    target: "es2022",
    sourcemap: false,
    assetsInlineLimit: 0,
    rollupOptions: {
      output: {
        manualChunks(id: string): string | undefined {
          if (!id.includes("node_modules")) {
            return undefined;
          }
          if (/\/@codemirror\/(?:state|view|language|autocomplete|commands|search|lint)\//u.test(id) ||
            /\/@lezer\/(?:common|lr|highlight)\//u.test(id)) {
            return "codemirror";
          }
          return undefined;
        },
      },
    },
  },
});
