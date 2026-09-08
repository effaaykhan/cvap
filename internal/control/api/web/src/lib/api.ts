// The typed API client. DTO types come from schema.ts, generated from the route
// registry's OpenAPI (openapi-typescript), so a response shape the UI reads
// cannot drift from the contract the server serves (ADR-043). The web CI job
// regenerates schema.ts and fails on a diff — the third registry that must agree.
import type { components } from "../api/schema";

type Schemas = components["schemas"];
export type Session = Schemas["SessionResponse"];
export type LoginResult = Schemas["LoginResponse"];
export type Finding = Schemas["FindingResponse"];
export type FindingList = Schemas["FindingListResponse"];
export type FindingSummary = Schemas["FindingSummaryResponse"];
export type Evidence = Schemas["EvidenceResponse"];
export type Exposure = Schemas["ExposureResponse"];
export type AssetList = Schemas["AssetListResponse"];
export type Asset = Schemas["AssetResponse"];
export type AssetSummary = Schemas["AssetSummary"];
export type ExposureByZone = Schemas["ExposureByZoneResponse"];
export type KnowledgeFreshness = Schemas["KnowledgeFreshnessResponse"];
export type KnowledgeFeed = Schemas["KnowledgeFeedResponse"];
export type Scan = Schemas["ScanResponse"];
export type ScanList = Schemas["ScanListResponse"];

// ApiError carries the server's stable code so a caller can branch — notably 403
// (forbidden), which the UI surfaces honestly rather than swallowing.
export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
  ) {
    super(message);
  }
}

// The CSRF token is the readable cvap_csrf cookie (HttpOnly:false), echoed into
// the X-CVAP-CSRF header on every mutation. The server compares it, constant
// time, against the session-bound token; an attacker can cause the session
// cookie to be sent but cannot read this cookie to set the header.
function csrfToken(): string {
  const m = document.cookie.match(/(?:^|;\s*)cvap_csrf=([^;]+)/);
  return m ? decodeURIComponent(m[1]) : "";
}

const MUTATING = new Set(["POST", "PUT", "PATCH", "DELETE"]);

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = {};
  const init: RequestInit = { method, credentials: "same-origin", headers };
  if (body !== undefined) {
    headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(body);
  }
  if (MUTATING.has(method)) headers["X-CVAP-CSRF"] = csrfToken();

  const res = await fetch(path, init);
  if (res.status === 204) return undefined as T;
  const text = await res.text();
  if (!res.ok) {
    let code = "error";
    let message = text;
    try {
      const b = JSON.parse(text);
      code = b.error ?? code;
      message = b.message ?? message;
    } catch {
      /* non-JSON error body; keep the text */
    }
    throw new ApiError(res.status, code, message);
  }
  return text ? (JSON.parse(text) as T) : (undefined as T);
}

export const api = {
  session: () => request<Session>("GET", "/v1/auth/session"),
  login: (email: string, password: string) =>
    request<LoginResult>("POST", "/v1/auth/login", { email, password }),
  logout: () => request<void>("POST", "/v1/auth/logout"),
  changePassword: (current_password: string, new_password: string) =>
    request<void>("POST", "/v1/auth/password", { current_password, new_password }),
  startOIDC: (returnTo?: string) =>
    request<Schemas["StartOIDCResponse"]>(
      "GET",
      "/v1/auth/oidc/start" + (returnTo ? `?return_to=${encodeURIComponent(returnTo)}` : ""),
    ),

  listFindings: (q: string) => request<FindingList>("GET", `/v1/findings${q}`),
  getFinding: (id: string) => request<Finding>("GET", `/v1/findings/${id}`),
  exposure: () => request<ExposureByZone>("GET", "/v1/exposure"),
  knowledgeFreshness: () => request<KnowledgeFreshness>("GET", "/v1/knowledge/freshness"),

  listAssets: (q: string) => request<AssetList>("GET", `/v1/assets${q}`),
  getAsset: (id: string) => request<Asset>("GET", `/v1/assets/${id}`),

  listPolicies: () => request<Schemas["PolicyListResponse"]>("GET", "/v1/policies"),

  listScans: (q: string) => request<ScanList>("GET", `/v1/scans${q}`),
  getScan: (id: string) => request<Scan>("GET", `/v1/scans/${id}`),
  createScan: (body: Schemas["CreateScanRequest"]) =>
    request<Scan>("POST", "/v1/scans", body),
  cancelScan: (id: string, reason: string) =>
    request<Scan>("POST", `/v1/scans/${id}/cancel`, { reason }),

  // CSV export is a browser navigation (a download), not a fetch: the file is
  // handed to the browser. The caller checks the permission first and surfaces a
  // 403 honestly (see ExportButton) rather than the UI pretending it is absent.
  exportURL: (kind: "findings" | "assets", q: string) => `/v1/${kind}.csv${q}`,
};

// has reports whether the session holds a permission — for REFLECTING RBAC in
// the UI. It is never the gate: the server ran the check that matters, and a
// hidden control is a courtesy, not a control.
export function has(session: Session | null, perm: string): boolean {
  return !!session?.permissions?.includes(perm);
}
