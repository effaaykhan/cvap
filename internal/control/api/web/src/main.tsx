import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter, HashRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { AuthProvider } from "./lib/auth";
import { App } from "./App";
import "./styles.css";

const qc = new QueryClient({
  defaultOptions: { queries: { retry: false, refetchOnWindowFocus: false } },
});

// BrowserRouter in every real deployment: Go serves dist/ at the origin root
// (ADR-053). A static preview of the bundle hosted under some other path — a
// design review page with a mocked API — has no server to rewrite routes, so a
// build with VITE_ROUTER=hash keeps navigation in the fragment. Build-time only;
// the production build never sets it.
const Router = import.meta.env.VITE_ROUTER === "hash" ? HashRouter : BrowserRouter;

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <QueryClientProvider client={qc}>
      <Router>
        <AuthProvider>
          <App />
        </AuthProvider>
      </Router>
    </QueryClientProvider>
  </StrictMode>,
);
