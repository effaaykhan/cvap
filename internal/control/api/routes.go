package api

import "net/http"

// The route table.
//
// One entry per endpoint, and the entry is the whole declaration: the path the
// mux serves, the authorisation the middleware enforces, and the schemas the
// OpenAPI document carries. They cannot drift because there is only one of them.
//
// Registration panics on a route that declares no Access, so an endpoint added
// here without deciding who may reach it stops the process at startup rather
// than becoming public.
func (s *Server) routes() {
	r := s.reg

	// ---------------------------------------------------------------- auth

	r.Register(Route{
		Method: http.MethodPost, Path: "/v1/auth/login",
		Summary: "Sign in",
		Description: "Local password authentication. Available only on an on-prem deployment " +
			"whose Core has local authentication enabled and whose tenant is configured for " +
			"it. The tenant comes from the request host and cannot be named in the body.",
		Access:   AccessPublic,
		Request:  LoginRequest{},
		Response: LoginResponse{},
		Handler:  s.login,
	})

	r.Register(Route{
		Method: http.MethodPost, Path: "/v1/auth/logout",
		Summary:     "Sign out",
		Description: "Revokes the current session. The row is kept, so the audit trail survives.",
		Access:      AccessSession,
		Status:      http.StatusNoContent,
		Handler:     s.logout,
	})

	r.Register(Route{
		Method: http.MethodGet, Path: "/v1/auth/session",
		Summary:     "Describe the current session",
		Description: "Who this session belongs to and what it may do.",
		Access:      AccessSession,
		Response:    SessionResponse{},
		Handler:     s.currentSession,
	})

	r.Register(Route{
		Method: http.MethodGet, Path: "/v1/auth/oidc/start",
		Summary: "Begin single sign-on",
		Description: "Returns the URL to send the browser to. Which identity provider that is " +
			"comes from the tenant this request's HOST resolved to, never from a parameter " +
			"(ADR-041). Mints a state, a nonce and a PKCE verifier bound to that tenant, all " +
			"single-use and valid for ten minutes. Optional ?return_to= must be a path on " +
			"this site: an absolute value would make the callback an open redirect.",
		Access:   AccessPublic,
		Response: StartOIDCResponse{},
		Handler:  s.startOIDC,
	})

	r.Register(Route{
		Method: http.MethodGet, Path: OIDCCallbackPath,
		Summary: "Complete single sign-on",
		Description: "Where the identity provider returns the browser. The state is redeemed " +
			"inside the tenant the callback's hostname resolved to, so a state minted at one " +
			"tenant cannot be replayed at another; the ID token's iss and aud are checked " +
			"against that tenant's configuration, and its nonce against the value minted for " +
			"this attempt. On success it issues the same session local login issues and " +
			"redirects to the recorded path.",
		Access:  AccessPublic,
		Status:  http.StatusSeeOther,
		Handler: s.callbackOIDC,
	})

	r.Register(Route{
		Method: http.MethodPost, Path: "/v1/auth/password",
		Summary: "Change this account's password",
		Description: "Requires the current password even when the account is flagged as needing " +
			"a change. Every session for the account ends, including this one.",
		Access:  AccessSession,
		Request: ChangePasswordRequest{},
		Status:  http.StatusNoContent,
		Handler: s.changePassword,
	})

	// --------------------------------------------------------------- scans

	r.Register(Route{
		Method: http.MethodPost, Path: "/v1/scans",
		Summary: "Create a scan",
		Description: "Every target must be attested as authorised; planning refuses a scan " +
			"whose targets are not. The scan is created safe — intrusive is a separate " +
			"operation with its own permission (ADR-021).",
		Access: AccessPermission, Permission: PermScanCreate,
		Request: CreateScanRequest{}, Response: ScanResponse{},
		Status:  http.StatusCreated,
		Handler: s.createScan,
	})

	r.Register(Route{
		Method: http.MethodGet, Path: "/v1/scans",
		Summary:     "List scans",
		Description: "Newest first. Pages by keyset cursor rather than offset, so rows do not shift under a client that is paging while scans are being created.",
		Access:      AccessPermission, Permission: PermScanRead,
		Response: ScanListResponse{},
		Handler:  s.listScans,
	})

	r.Register(Route{
		Method: http.MethodGet, Path: "/v1/scans/{scan_id}",
		Summary: "Get a scan",
		Access:  AccessPermission, Permission: PermScanRead,
		Response: ScanResponse{},
		Handler:  s.getScan,
	})

	r.Register(Route{
		Method: http.MethodPost, Path: "/v1/scans/{scan_id}/cancel",
		Summary: "Cancel a scan",
		Description: "Queued jobs stop being claimable immediately; in-flight jobs are told to " +
			"stop on the next dispatch pass, naming the lease epoch. A scan that has already " +
			"finished is refused rather than silently accepted.",
		Access: AccessPermission, Permission: PermScanCancel,
		Request: CancelScanRequest{}, Response: ScanResponse{},
		Handler: s.cancelScan,
	})

	r.Register(Route{
		Method: http.MethodPut, Path: "/v1/scans/{scan_id}/safety-mode",
		Summary: "Choose a scan's safety mode",
		Description: "ADR-021's per-scan opt-in. The policy is the ceiling and a scan opts in " +
			"beneath it; a scan under a safe policy cannot make itself intrusive. Only before " +
			"the scan starts — cancellation is the lever for one already running. Both " +
			"choices are recorded in the audit log, because 'no event' would otherwise mean " +
			"both 'nobody chose' and 'somebody chose safe'.",
		Access: AccessPermission, Permission: PermScanIntrusive,
		Request: SafetyModeRequest{}, Response: ScanResponse{},
		Handler: s.setSafetyMode,
	})

	// ---------------------------------------------------------------- kill

	r.Register(Route{
		Method: http.MethodPost, Path: "/v1/kill",
		Summary: "Issue a kill switch",
		Description: "ADR-024 control 4: stops scanning across the fleet, a zone, or one scan. " +
			"Propagation is bounded at ten seconds and that bound is not adjustable.",
		Access: AccessPermission, Permission: PermKillIssue,
		Request: IssueKillRequest{}, Response: KillResponse{},
		Status:  http.StatusCreated,
		Handler: s.issueKill,
	})

	r.Register(Route{
		Method: http.MethodPost, Path: "/v1/kill/{kill_id}/resolve",
		Summary: "Resolve a kill switch",
		Description: "Lets scanning resume. A separate permission from issuing one: deciding " +
			"the emergency is over is a different judgement from stopping the fleet.",
		Access: AccessPermission, Permission: PermKillResolve,
		Status:  http.StatusNoContent,
		Handler: s.resolveKill,
	})

	// -------------------------------------------------------------- policy

	r.Register(Route{
		Method: http.MethodPost, Path: "/v1/policies",
		Summary: "Create a scan policy",
		Access:  AccessPermission, Permission: PermPolicyWrite,
		Request: PolicyRequest{}, Response: PolicyResponse{},
		Status:  http.StatusCreated,
		Handler: s.createPolicy,
	})

	r.Register(Route{
		Method: http.MethodGet, Path: "/v1/policies",
		Summary: "List scan policies",
		Access:  AccessPermission, Permission: PermPolicyRead,
		Response: PolicyListResponse{},
		Handler:  s.listPolicies,
	})

	r.Register(Route{
		Method: http.MethodGet, Path: "/v1/policies/{policy_id}",
		Summary: "Get a scan policy",
		Access:  AccessPermission, Permission: PermPolicyRead,
		Response: PolicyResponse{},
		Handler:  s.getPolicy,
	})

	r.Register(Route{
		Method: http.MethodPut, Path: "/v1/policies/{policy_id}",
		Summary: "Replace a scan policy",
		Description: "A full replacement rather than a patch. For a constraint list where " +
			"empty means unrestricted (ADR-037), 'I did not send it' and 'I sent nothing' " +
			"would otherwise be two different things that look identical in a body.",
		Access: AccessPermission, Permission: PermPolicyWrite,
		Request: PolicyRequest{}, Response: PolicyResponse{},
		Handler: s.updatePolicy,
	})

	r.Register(Route{
		Method: http.MethodGet, Path: "/v1/policies/{policy_id}/scope-rules",
		Summary: "List a policy's scope rules",
		Access:  AccessPermission, Permission: PermPolicyRead,
		Response: ScopeRuleListResponse{},
		Handler:  s.listScopeRules,
	})

	r.Register(Route{
		Method: http.MethodPost, Path: "/v1/policies/{policy_id}/scope-rules",
		Summary: "Add a scope rule",
		Description: "Exclusions take precedence over allows regardless of precedence value. " +
			"An allow list is a permission list: empty denies (ADR-037).",
		Access: AccessPermission, Permission: PermPolicyWrite,
		Request: ScopeRuleRequest{}, Response: ScopeRuleResponse{},
		Status:  http.StatusCreated,
		Handler: s.addScopeRule,
	})

	r.Register(Route{
		Method: http.MethodDelete, Path: "/v1/policies/{policy_id}/scope-rules/{rule_id}",
		Summary: "Delete a scope rule",
		Description: "Deleting a deny rule widens what may be scanned. The audit event records " +
			"what the rule said, because the row will not exist to be read afterwards.",
		Access: AccessPermission, Permission: PermPolicyWrite,
		Status:  http.StatusNoContent,
		Handler: s.deleteScopeRule,
	})

	// --------------------------------------------------- zones, scan points

	r.Register(Route{
		Method: http.MethodPost, Path: "/v1/zones",
		Summary: "Create a scan zone",
		Access:  AccessPermission, Permission: PermZoneWrite,
		Request: ZoneRequest{}, Response: ZoneResponse{},
		Status:  http.StatusCreated,
		Handler: s.createZone,
	})

	r.Register(Route{
		Method: http.MethodGet, Path: "/v1/zones",
		Summary: "List scan zones",
		Access:  AccessPermission, Permission: PermZoneRead,
		Response: ZoneListResponse{},
		Handler:  s.listZones,
	})

	r.Register(Route{
		Method: http.MethodPost, Path: "/v1/zones/{zone_id}/ranges",
		Summary: "Add a network range to a zone",
		Access:  AccessPermission, Permission: PermZoneWrite,
		Request: NetworkRangeRequest{}, Response: NetworkRangeResponse{},
		Status:  http.StatusCreated,
		Handler: s.addNetworkRange,
	})

	r.Register(Route{
		Method: http.MethodGet, Path: "/v1/zones/{zone_id}/scan-points",
		Summary: "List a zone's scan points",
		Description: "Certificate fingerprints are not returned: a fingerprint is a scan " +
			"point's authentication identity and the input to its tenant resolution.",
		Access: AccessPermission, Permission: PermScanPointRead,
		Response: ScanPointListResponse{},
		Handler:  s.listScanPoints,
	})

	r.Register(Route{
		Method: http.MethodPost, Path: "/v1/enrollment-tokens",
		Summary: "Issue an enrollment token",
		Description: "Single use, TTL-bounded, carrying the tenant AND the zone. A scan point " +
			"asserts neither — the zone above all, because exposure is derived from the " +
			"vantage point an observation was made from (ADR-008, ADR-018). The token value " +
			"is shown once and cannot be retrieved again.",
		Access: AccessPermission, Permission: PermScanPointEnroll,
		Request: EnrollmentTokenRequest{}, Response: EnrollmentTokenResponse{},
		Status:  http.StatusCreated,
		Handler: s.issueEnrollmentToken,
	})

	r.Register(Route{
		Method: http.MethodGet, Path: "/v1/scan-points",
		Summary: "List all scan points (fleet health)",
		Description: "Every scan point in the tenant, worst-first by liveness, so the UI shows " +
			"fleet health without iterating zones. Certificate fingerprints are never returned.",
		Access: AccessPermission, Permission: PermScanPointRead,
		Response: ScanPointListResponse{},
		Handler:  s.listAllScanPoints,
	})

	// ----------------------------------------------------------- assets

	r.Register(Route{
		Method: http.MethodGet, Path: "/v1/assets",
		Summary: "List assets",
		Description: "The asset inventory, newest-seen first, by keyset cursor. Filter with " +
			"?q= (hostname or a current address), ?environment=, ?fragile=true|false.",
		Access: AccessPermission, Permission: PermAssetRead,
		Response: AssetListResponse{},
		Handler:  s.listAssets,
	})

	// ------------------------------------------------------------ identity

	r.Register(Route{
		Method: http.MethodGet, Path: "/v1/identity/queue",
		Summary: "List the identity resolution queue",
		Description: "Everything correlation parked for an operator (ADR-007, ADR-094, ADR-096), grouped by " +
			"address, newest contest first: the candidates the evidence was judged against, the verdict's " +
			"reason (including which continuity fact failed), and the parked keys with their copied evidence.",
		Access: AccessPermission, Permission: PermAssetRead,
		Response: IdentityQueueResponse{},
		Handler:  s.listIdentityQueue,
	})

	r.Register(Route{
		Method: http.MethodPost, Path: "/v1/identity/queue/resolve",
		Summary: "Adjudicate a contested address",
		Description: "same_host: the parked keys are the named asset's — its held key of the same service is retired, " +
			"the parked one recorded as confirmed, and the parked observations attach to it on the next sweep. " +
			"different_host: the parked group is a host of its own — a new asset holding the parked keys takes the " +
			"address. An operator's decision, recorded with the operator; it verifies nothing (B44). A key another " +
			"asset holds live is never moved by either verb (that merge is B40).",
		Access: AccessPermission, Permission: PermIdentityResolve,
		Request: ResolveIdentityRequest{}, Response: ResolveIdentityResponse{},
		Handler: s.resolveIdentity,
	})

	r.Register(Route{
		Method: http.MethodPost, Path: "/v1/assets/{asset_id}/identity/confirm",
		Summary: "Confirm a rotated or lapsed key",
		Description: "A key recorded by a rotation or a lapse (ADR-096) is excluded from the credentialed trust " +
			"root until an operator confirms it. This is that confirmation: the key is re-stamped confirmed and is " +
			"trust material on ADR-094's terms (two sightings at the address). Recorded with the operator; it " +
			"verifies nothing (B44) — an operator who confirms a key an attacker rotated in has handed that attacker " +
			"the credentialed dial.",
		Access: AccessPermission, Permission: PermIdentityResolve,
		Request: ConfirmIdentityRequest{}, Response: ConfirmIdentityResponse{},
		Handler: s.confirmIdentity,
	})

	r.Register(Route{
		Method: http.MethodGet, Path: "/v1/assets/{asset_id}",
		Summary: "Get an asset",
		Description: "Current addresses (time-bounded, ADR-008), listening services, and the " +
			"count of open findings. Assets are derived from observations, never written by a scan point (ADR-006).",
		Access: AccessPermission, Permission: PermAssetRead,
		Response: AssetResponse{},
		Handler:  s.getAsset,
	})

	// ----------------------------------------------------------- findings

	r.Register(Route{
		Method: http.MethodGet, Path: "/v1/findings",
		Summary: "List findings",
		Description: "Newest-seen first, by keyset cursor. Filter with ?status=, ?severity=, " +
			"?asset_id=, ?rule_id=. One finding seen from several zones is one row (ADR-010).",
		Access: AccessPermission, Permission: PermFindingRead,
		Response: FindingListResponse{},
		Handler:  s.listFindings,
	})

	r.Register(Route{
		Method: http.MethodGet, Path: "/v1/findings/{finding_id}",
		Summary: "Get a finding, with the evidence a human verifies it by",
		Description: "The finding, its rule and remediation, every vantage point it is exposed " +
			"from, and the evidence copied from the observation at finding creation (ADR-016). " +
			"When an observation has aged out, its evidence remains and the response says so " +
			"rather than showing a dead link.",
		Access: AccessPermission, Permission: PermFindingRead,
		Response: FindingResponse{},
		Handler:  s.getFinding,
	})

	r.Register(Route{
		Method: http.MethodGet, Path: "/v1/exposure",
		Summary: "Exposure by zone",
		Description: "Open findings visible from each zone, by severity, worst-first (ADR-008). " +
			"Each count is DISTINCT findings for that zone; the counts are not summable across " +
			"zones, because a finding seen from three zones is one finding (ADR-010).",
		Access: AccessPermission, Permission: PermFindingRead,
		Response: ExposureByZoneResponse{},
		Handler:  s.exposureByZone,
	})

	r.Register(Route{
		Method: http.MethodGet, Path: "/v1/knowledge/freshness",
		Summary: "Knowledge feed freshness",
		Description: "Ingested vendor-advisory feeds and whether each is current or stale " +
			"(ADR-014, ADR-063). `state` is computed server-side against each feed's own " +
			"staleness threshold, stored in the data — a stale feed means advisory matching " +
			"is under-reporting, so the state is surfaced, not inferred from the timestamp.",
		Access: AccessPermission, Permission: PermFindingRead,
		Response: KnowledgeFreshnessResponse{},
		Handler:  s.knowledgeFreshness,
	})

	r.Register(Route{
		Method: http.MethodGet, Path: "/v1/findings/summary",
		Summary: "Finding summary for the operator landing",
		Description: "Exact open and KEV counts, what changed inside a fixed window (`days`, default 7: " +
			"new, resolved, reopened, newly KEV-listed, with the worst named), and a daily open/KEV " +
			"series (`trend_days`, default 30) derived from first_seen and resolved_at. Every number " +
			"is a count of findings the list endpoint pages over; nothing is a rollup with its own life.",
		Access: AccessPermission, Permission: PermFindingRead,
		Response: FindingSummaryStatsResponse{},
		Handler:  s.findingSummaryStats,
	})

	r.Register(Route{
		Method: http.MethodGet, Path: "/v1/health",
		Summary: "Pipeline and safety health",
		Description: "What is not working, from server-owned state: scans whose queued jobs no scan point " +
			"can claim (the same predicate scan creation refuses on), the ingest backlog and unresolved " +
			"observations over the last 7 days, unresolved kill switches with their unacknowledged scan " +
			"points, and credential releases past expiry with no zeroisation attestation. Nothing here " +
			"is inferred by the client.",
		Access: AccessPermission, Permission: PermScanRead,
		Response: HealthResponse{},
		Handler:  s.health,
	})

	r.Register(Route{
		Method: http.MethodGet, Path: "/v1/findings.csv",
		Summary: "Export findings as CSV",
		Description: "The findings list (same filters) as CSV, for the reporting §2 permits. " +
			"Bounded: an export matching more than the cap is REFUSED with 422 rather than " +
			"truncated, so an incomplete file never masquerades as complete — narrow it with a " +
			"filter. Gated by finding.export_all, a heavier authority than finding.read: pulling " +
			"the whole set into a file is exfiltration shaped like a feature (ADR-052).",
		Access: AccessPermission, Permission: PermFindingExportAll,
		ResponseContentType: "text/csv",
		Handler:             s.exportFindingsCSV,
	})

	r.Register(Route{
		Method: http.MethodGet, Path: "/v1/assets.csv",
		Summary: "Export assets as CSV",
		Description: "The asset inventory (same filters) as CSV. Bounded and refusing over the " +
			"cap, exactly as the findings export (ADR-052). Gated by asset.export_all, held by " +
			"operator and above rather than every reader.",
		Access: AccessPermission, Permission: PermAssetExportAll,
		ResponseContentType: "text/csv",
		Handler:             s.exportAssetsCSV,
	})

	// ----------------------------------------------------------- discovery

	r.Register(Route{
		Method: http.MethodGet, Path: "/v1/openapi.json",
		Summary: "This API's OpenAPI document",
		Description: "Rendered from the route registry on each request, not hand-maintained. " +
			"Public because a client needs it before it can authenticate, and it describes " +
			"the shape of the API rather than anything about this tenant.",
		Access:  AccessPublic,
		Handler: s.openAPIDoc,
	})

	// The operator web UI, same-origin, as the last (catch-all) route so /v1/*
	// match first. Static and excluded from the OpenAPI document (ADR-053).
	s.registerSPA()
}

// openAPIDoc serves the generated document.
func (s *Server) openAPIDoc(w http.ResponseWriter, r *http.Request) {
	doc, err := s.reg.OpenAPI(s.cfg.Version)
	if err != nil {
		writeError(w, r, s.log, http.StatusInternalServerError, CodeInternal,
			"An unexpected error occurred.", err)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(doc); err != nil {
		s.log.Warn("failed to write the OpenAPI document",
			"request_id", requestIDFrom(r.Context()), "err", err)
	}
}
