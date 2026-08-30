// Package control holds the Control Plane services: authentication and RBAC,
// tenancy, asset management, scan orchestration and policy.
//
// The Control Plane decides and never scans. It owns the derivation of assets
// and findings from observations (ADR-006) and the planning-side half of scope
// enforcement (ADR-024).
package control
