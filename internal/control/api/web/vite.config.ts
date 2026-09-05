import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Same-origin in production: Go serves dist/ (ADR-053). In dev, the API is
// proxied so the browser sees one origin — no CORS, and the proxied Host strips
// to localhost, which is a real tenants.domain row (ADR-041).
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      "/v1": { target: "http://127.0.0.1:8080", changeOrigin: false },
    },
  },
  build: { outDir: "dist", emptyOutDir: true },
  test: { environment: "jsdom", globals: true, setupFiles: ["src/test-setup.ts"] },
});
