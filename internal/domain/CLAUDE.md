# internal/domain

Pure model. **No I/O in this package** — no database, no network, no filesystem, no clock
reads outside an injected interface. If a change here needs a dependency, the change
belongs somewhere else.

Holds: Observation, Asset, AssetIdentityKey, AssetAddress, Service, SoftwareComponent,
Finding, Exposure, Evidence, Rule, VulnerabilityDef, VendorAdvisory.

Invariants enforced by type where possible rather than by convention:

- Observation is immutable once constructed.
- Asset has no zone field. Do not add one.
- AssetAddress and AssetIdentityKey carry a validity interval, never a bare current value.
- Finding requires a RuleID; VulnDefID is an option type.
- Exposure is a set on the finding, not a scalar.

Identity resolution logic lives here and must be a pure function of observations, so it
can be re-run over history without re-scanning.
