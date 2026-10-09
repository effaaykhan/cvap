import { useEffect, useId, useRef, useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { useQueries, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError, has, type BlockedScan, type Health, type Policy, type Scan } from "../lib/api";
import { useAuth } from "../lib/auth";
import { PageHead } from "../components/PageHead";
import { Pager, PAGE_ROWS, TableWrap } from "../components/Discovery";
import { shortDate } from "../lib/discovery";
import { ago } from "../lib/console";
import {
  countLabel, distinct, elapsedLabel, emptyResultMessage, filterScans, IN_FLIGHT, IN_FLIGHT_CHIP, IN_FLIGHT_LABEL,
  isInFlight, killsFor, newestFirst, portList, requesterFull, requesterLabel, SCAN_PAGE, summarizeResults,
  type InFlight, type RunningFilter,
} from "../lib/scans";

// Running Scans: every scan requested and not yet finished, from /v1/scans —
// one read per in-flight status, because the endpoint filters by one status at
// a time. Core records a scan's state and timestamps, not its progress, so the
// page shows how long each has waited or run and nothing that looks like a
// percentage. Blocked is health's operational verdict on a scan, not a status.
const POLL_MS = 15_000;

export function RunningScans() {
  const { session } = useAuth();
  const qc = useQueryClient();
  const lists = useQueries({
    queries: IN_FLIGHT.map((st) => {
      const q = `?status=${st}&limit=${SCAN_PAGE}`;
      return { queryKey: ["scans", q], queryFn: () => api.listScans(q), refetchInterval: POLL_MS };
    }),
  });
  const health = useQuery({ queryKey: ["health"], queryFn: () => api.health(), refetchInterval: POLL_MS });
  const policies = useQuery({ queryKey: ["policies"], queryFn: () => api.listPolicies(), enabled: has(session, "policy.read") });

  const [filter, setFilter] = useState<RunningFilter>({ status: "", type: "", policy: "", mine: false });
  const [page, setPage] = useState(0);
  const [viewing, setViewing] = useState<Scan | null>(null);
  const [cancelling, setCancelling] = useState<Scan | null>(null);
  const [notice, setNotice] = useState("");

  // Elapsed times keep moving between reads.
  const [now, setNow] = useState(Date.now());
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 5_000);
    return () => clearInterval(t);
  }, []);

  const byStatus = Object.fromEntries(IN_FLIGHT.map((st, i) => [st, lists[i]])) as Record<InFlight, (typeof lists)[number]>;
  const all = newestFirst(lists.flatMap((l) => l.data?.scans ?? []).filter((s) => isInFlight(s.status)));
  const rows = filterScans(all, filter, session?.user_id);
  const visible = rows.slice(page * PAGE_ROWS, (page + 1) * PAGE_ROWS);

  const blockedScans = new Map((health.data?.blocked_scans ?? []).map((b) => [b.id, b]));
  const blocked = new Map([...blockedScans].map(([id, b]) => [id, b.reason]));
  const policyByID = new Map((policies.data?.policies ?? []).map((p) => [p.id, p]));
  const policyName = new Map([...policyByID].map(([id, p]) => [id, p.name]));
  const policyLabel = (id: string) => policyName.get(id) ?? id.slice(0, 8);

  const loading = lists.some((l) => l.isLoading);
  const failed = lists.filter((l) => l.error).map((l) => l.error);
  const fetching = lists.some((l) => l.isFetching) || health.isFetching;
  const refreshedAt = Math.max(0, ...lists.map((l) => l.dataUpdatedAt));
  const refresh = () => {
    setNotice("");
    void Promise.all([...lists.map((l) => l.refetch()), health.refetch()]);
  };
  const setF = (next: Partial<RunningFilter>) => {
    setFilter((f) => ({ ...f, ...next }));
    setPage(0);
  };

  return (
    <section className="running-scans">
      <PageHead
        title="Running Scans"
        sub="Monitor scans that are pending, planning, or currently running."
        action={
          <div className="rs-refresh">
            <span className="rs-refreshed">
              {refreshedAt ? <>Last refreshed <span className="data">{new Date(refreshedAt).toLocaleTimeString()}</span></> : "Not refreshed yet"}
            </span>
            <button type="button" onClick={refresh} disabled={fetching}>{fetching ? "Refreshing…" : "Refresh"}</button>
          </div>
        }
      />

      <div className="rs-summary" aria-label="Status summary">
        {IN_FLIGHT.map((st) => (
          <div key={st} className="card rs-tile">
            <span className="lbl"><span className={`dot dot-${st === "pending" ? "medium" : st === "planning" ? "accent" : "ok"}`} /> {IN_FLIGHT_LABEL[st]}</span>
            <span className={`rs-count rs-count-${st}`}>{byStatus[st].error ? "—" : countLabel(byStatus[st].data)}</span>
          </div>
        ))}
        {/* Only when health actually answered: an absent read is not zero. */}
        {health.data && (
          <div className="card rs-tile" title="Scans no online, capable scan point in a permitted zone can run. A condition, not a status.">
            <span className="lbl"><span className="dot dot-danger" /> Blocked</span>
            <span className="rs-count rs-count-blocked">{health.data.blocked_scans.length}</span>
          </div>
        )}
      </div>

      <div className="rs-filters" role="group" aria-label="Filters">
        <label>
          <span className="lbl">Status</span>
          <select value={filter.status} onChange={(e) => setF({ status: e.target.value as RunningFilter["status"] })}>
            <option value="">All</option>
            {IN_FLIGHT.map((st) => <option key={st} value={st}>{IN_FLIGHT_LABEL[st]}</option>)}
          </select>
        </label>
        <label>
          <span className="lbl">Type</span>
          <select value={filter.type} onChange={(e) => setF({ type: e.target.value })}>
            <option value="">All</option>
            {distinct(all.map((s) => s.scan_type)).map((t) => <option key={t} value={t}>{t}</option>)}
          </select>
        </label>
        <label>
          <span className="lbl">Policy</span>
          <select value={filter.policy} onChange={(e) => setF({ policy: e.target.value })}>
            <option value="">All</option>
            {distinct(all.map((s) => s.policy_id)).map((p) => <option key={p} value={p}>{policyLabel(p)}</option>)}
          </select>
        </label>
        <button type="button" className={`filt${filter.mine ? " on" : ""}`} aria-pressed={filter.mine} onClick={() => setF({ mine: !filter.mine })}>
          Requested by me
        </button>
      </div>

      <div className="card section rs-table">
        <div className="card-head">
          <span className="lbl">In-flight scans</span>
          <Pager page={page} total={rows.length} onPage={setPage} />
        </div>
        {notice && <p className="muted small rs-notice" role="status">{notice}</p>}
        {failed.length > 0 && (
          <p className="error small">
            {failed.some((e) => e instanceof ApiError && e.status === 403)
              ? "This account cannot read scans (it lacks the scan.read permission)."
              : "Could not load every in-flight status; the table shows what did load."}
          </p>
        )}
        {loading ? (
          <p className="muted">Loading…</p>
        ) : rows.length === 0 ? (
          <p className="empty">
            {all.length === 0 ? "No scans are pending, planning or running." : "No in-flight scans match these filters."}
          </p>
        ) : (
          <TableWrap>
            <table>
              <thead>
                <tr>
                  <th>Scan ID</th><th>Type</th><th>Status</th><th>Safety Mode</th><th>Policy</th><th>Requested By</th>
                  <th>Requested At</th><th>Started At</th><th>Waiting / Running</th><th className="rs-actions-h">Actions</th>
                </tr>
              </thead>
              <tbody>
                {visible.map((s) => (
                  <tr key={s.id}>
                    <td className="data" title={s.id}>{s.id.slice(0, 8)}</td>
                    <td className="data">{s.scan_type}</td>
                    <td><StatusChips scan={s} blockedReason={blocked.get(s.id)} /></td>
                    <td><SafetyChip mode={s.safety_mode} /></td>
                    <td className="data rs-policy" title={`${policyLabel(s.policy_id)} · ${s.policy_id}`}>{policyLabel(s.policy_id)}</td>
                    <td className="data" title={s.requested_by ?? "requested by Core"}>{requesterLabel(s.requested_by, session?.user_id)}</td>
                    <td className="data">{shortDate(s.created_at)}</td>
                    <td className="data">{shortDate(s.started_at)}</td>
                    <td className="data">{elapsedLabel(s, now)}</td>
                    <td className="rs-actions">
                      <button type="button" className="rs-btn" onClick={() => setViewing(s)} aria-label={`View scan ${s.id.slice(0, 8)}`}>View</button>
                      <button type="button" className="rs-btn rs-btn-danger" disabled={!has(session, "scan.cancel")}
                        title={has(session, "scan.cancel") ? undefined : "Requires the scan.cancel permission, which this account does not hold."}
                        onClick={() => { setNotice(""); setCancelling(s); }} aria-label={`Cancel scan ${s.id.slice(0, 8)}`}>Cancel</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </TableWrap>
        )}
      </div>

      {viewing && (
        <ScanDrawer scan={viewing} now={now} policyLabel={policyLabel} blocked={blockedScans.get(viewing.id)}
          policy={has(session, "policy.read") ? policyByID.get(viewing.policy_id) : undefined}
          kills={health.data?.active_kills ?? []} sessionUserID={session?.user_id} onClose={() => setViewing(null)} />
      )}
      {cancelling && (
        <CancelDialog
          scan={cancelling}
          onClose={() => setCancelling(null)}
          onCancelled={(s) => {
            setCancelling(null);
            setNotice(`Scan ${s.id.slice(0, 8)} cancelled.`);
            void qc.invalidateQueries({ queryKey: ["scans"] });
            void qc.invalidateQueries({ queryKey: ["scan", s.id] });
            void qc.invalidateQueries({ queryKey: ["health"] });
          }}
        />
      )}
    </section>
  );
}

function StatusChips({ scan, blockedReason }: { scan: Scan; blockedReason?: string }) {
  const st = isInFlight(scan.status) ? scan.status : null;
  return (
    <span className="rs-status">
      <span className={`chip chip-${st ? IN_FLIGHT_CHIP[st] : "muted"}`}>{st ? IN_FLIGHT_LABEL[st] : scan.status}</span>
      {blockedReason !== undefined && <span className="chip chip-danger" title={blockedReason}>Blocked</span>}
    </span>
  );
}

function SafetyChip({ mode }: { mode: string }) {
  return <span className={`chip chip-${mode === "intrusive" ? "high" : "muted"}`}>{mode}</span>;
}

// The View drawer. The row is the starting point; the scan is re-read so a
// state change while it is open (a scan finishing) shows rather than a stale
// row. Observed results lead: they are the one thing the table cannot show.
// Facts the table already carries collapse into the header line.
function ScanDrawer({ scan, now, policyLabel, blocked, policy, kills, sessionUserID, onClose }: {
  scan: Scan; now: number; policyLabel: (id: string) => string; blocked?: BlockedScan; policy?: Policy;
  kills: Health["active_kills"]; sessionUserID?: string; onClose: () => void;
}) {
  const titleId = useId();
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => ref.current?.focus(), []);
  const fresh = useQuery({ queryKey: ["scan", scan.id], queryFn: () => api.getScan(scan.id), refetchInterval: POLL_MS });
  const s = fresh.data ?? scan;
  const results = useQuery({
    queryKey: ["scan-results", scan.id],
    queryFn: () => api.scanResults(scan.id),
    refetchInterval: isInFlight(s.status) ? 10_000 : false,
  });
  const r = results.data;
  const sum = r ? summarizeResults(r) : null;
  const applying = killsFor(s.id, kills);
  return (
    <>
      <div className="rs-backdrop" onClick={onClose} />
      <div className="rs-drawer" role="dialog" aria-modal="true" aria-labelledby={titleId} tabIndex={-1} ref={ref}
        onKeyDown={(e) => { if (e.key === "Escape") onClose(); }}>
        <div className="rs-drawer-head">
          <h2 id={titleId}>Scan <span className="data">{s.id.slice(0, 8)}</span></h2>
          <button type="button" className="rs-btn" onClick={onClose} aria-label="Close">Close</button>
        </div>
        <div className="rs-drawer-meta" aria-label="Scan summary">
          <StatusChips scan={s} blockedReason={blocked?.reason} />
          <span className="chip chip-muted data">{s.scan_type}</span>
          <SafetyChip mode={s.safety_mode} />
          <span className="data rs-drawer-elapsed">{isInFlight(s.status) ? elapsedLabel(s, now) : `finished · ${s.status}`}</span>
        </div>

        {applying.map((k) => (
          <div key={k.id} className="rs-alert" role="note">
            <b>Kill switch active ({k.scope})</b> — {k.reason}
            {k.unacknowledged > 0 && <> · {k.unacknowledged} scan point{k.unacknowledged === 1 ? "" : "s"} not yet acknowledged</>}
          </div>
        ))}
        {blocked && (
          <div className="rs-alert" role="note">
            <b>Blocked</b> — {blocked.reason} <span className="faint">· engine <span className="data">{blocked.engine}</span></span>
          </div>
        )}

        <h3 className="rs-sub">Observed Results (So Far)</h3>
        {results.error ? (
          <p className="error small" role="alert">
            Could not load results{results.error instanceof ApiError && results.error.message ? `: ${results.error.message}` : "."}
          </p>
        ) : !r || !sum ? (
          <p className="muted small">Loading…</p>
        ) : r.ports.length === 0 ? (
          <p className="muted small rs-empty-results">{emptyResultMessage(s)}</p>
        ) : (
          <>
            <div className="rs-observed">
              <div className="card rs-tile">
                <span className="lbl">Hosts Observed</span>
                <span className="rs-count">{sum.hosts}</span>
              </div>
              <div className="card rs-tile">
                <span className="lbl">Open-Port Observations</span>
                <span className="rs-count">{sum.observations}</span>
              </div>
            </div>
            {sum.latest && (
              <p className="small rs-latest">Latest observation <span className="data">{ago(sum.latest)}</span>
                <span className="faint"> · {shortDate(sum.latest)}</span></p>
            )}
            <ul className="rs-hosts" aria-label="Ports by host">
              {sum.shown.map(([address, ports]) => (
                <li key={address}><span className="data">{address}</span> <span className="faint">→</span> <span className="data">{portList(ports)}</span></li>
              ))}
            </ul>
            {sum.more > 0 && <p className="faint small">+{sum.more} more host{sum.more === 1 ? "" : "s"}</p>}
            {r.truncated && (
              <p className="faint small">Showing only the first {r.limit.toLocaleString()} records; the counts above may be incomplete.</p>
            )}
          </>
        )}
        <p className="muted small">Partial and current observations. Subject to change.</p>
        <p className="faint small">Results appear once accepted by ingest and age out over time.</p>
        <p className="small"><Link to={`/scans/${s.id}`}>Open full results →</Link></p>

        <h3 className="rs-sub">Details</h3>
        <dl className="rs-facts">
          <div><dt>Scan ID</dt><dd className="data">{s.id}</dd></div>
          <div><dt>Policy</dt><dd className="data">{policyLabel(s.policy_id)}<span className="faint"> · {s.policy_id}</span></dd></div>
          <div><dt>Requested By</dt><dd className="data">{requesterFull(s.requested_by, sessionUserID)}</dd></div>
          <div><dt>Requested At</dt><dd className="data">{shortDate(s.created_at)}</dd></div>
        </dl>

        {policy && (
          <>
            <h3 className="rs-sub">Policy limits</h3>
            <dl className="rs-facts">
              <div><dt>Safety ceiling</dt><dd><SafetyChip mode={policy.safety_mode} /></dd></div>
              <div><dt>Max rate</dt><dd className="data">{policy.max_rate_pps != null ? `${policy.max_rate_pps} pps` : "not set"}</dd></div>
              <div><dt>Max concurrent per target</dt><dd className="data">{policy.max_concurrent_per_target ?? "not set"}</dd></div>
            </dl>
          </>
        )}
      </div>
    </>
  );
}

// Cancel asks for the reason the API requires and records; the server's
// refusal (a scan that already finished, a missing permission) is shown as it
// is rather than reported as success.
function CancelDialog({ scan, onClose, onCancelled }: { scan: Scan; onClose: () => void; onCancelled: (s: Scan) => void }) {
  const titleId = useId();
  const reasonId = useId();
  const ref = useRef<HTMLTextAreaElement>(null);
  useEffect(() => ref.current?.focus(), []);
  const [reason, setReason] = useState("");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!reason.trim() || busy) return;
    setBusy(true);
    setErr("");
    try {
      onCancelled(await api.cancelScan(scan.id, reason.trim()));
    } catch (x) {
      setErr(x instanceof ApiError ? x.message : "Could not cancel the scan.");
      setBusy(false);
    }
  };
  return (
    <>
      <div className="rs-backdrop" onClick={onClose} />
      <form className="card rs-dialog" role="dialog" aria-modal="true" aria-labelledby={titleId} onSubmit={submit}
        onKeyDown={(e) => { if (e.key === "Escape") onClose(); }}>
        <h2 id={titleId}>Cancel scan <span className="data">{scan.id.slice(0, 8)}</span>?</h2>
        <p className="muted small">
          Queued jobs stop being claimable at once; jobs already running are told to stop. A scan that has already finished is refused.
        </p>
        <label htmlFor={reasonId} className="lbl">Reason <span className="faint">· required, recorded in the audit log</span></label>
        <textarea id={reasonId} ref={ref} rows={3} value={reason} onChange={(e) => setReason(e.target.value)} placeholder="Why is this scan being stopped?" />
        {err && <p className="error small" role="alert">{err}</p>}
        <div className="rs-dialog-actions">
          <button type="button" className="rs-btn" onClick={onClose}>Keep scan</button>
          <button type="submit" className="rs-btn rs-btn-danger rs-btn-solid" disabled={!reason.trim() || busy}>{busy ? "Cancelling…" : "Cancel scan"}</button>
        </div>
      </form>
    </>
  );
}
