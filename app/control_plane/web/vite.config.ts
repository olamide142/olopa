import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import { fileURLToPath, URL } from "node:url";

// The console SPA is served by the FastAPI control plane.
//  - Built assets are emitted into ../control_server/webdist
//  - They are referenced under the /ui/ base and served via a StaticFiles mount.
//  - index.html is returned by the dashboard router at "/".
export default defineConfig({
  base: "/ui/",
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      "@": fileURLToPath(new URL("./src", import.meta.url)),
    },
  },
  build: {
    outDir: fileURLToPath(new URL("../control_server/webdist", import.meta.url)),
    emptyOutDir: true,
  },
  server: {
    port: 5173,
    // index.css imports the shared design tokens from ../../design.
    fs: { allow: [".", "../../design"] },
    proxy: {
      // In dev, proxy API calls to the running control plane.
      "/api": "http://127.0.0.1:8100",
      "/health": "http://127.0.0.1:8100",
    },
  },
});
