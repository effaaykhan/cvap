import type { ReactNode } from "react";
import { Link } from "react-router-dom";
import { Donut } from "./Charts";
import { assetLabel, PORT_STATE_ORDER, PORT_STATES, type PortState } from "../lib/discovery";

// The building blocks the Discover pages share, so five pages read as one
// module: the same metric tile as the Dashboard, the same card section, one
// way to name an asset, one way to say "this is all the server gave us".

export function Metric({ label, value, qual, foot, tone }: {
  label: string; value: ReactNode; qual?: ReactNode; foot?: ReactNode; tone?: "warn" | "danger" | "ok" | "accent";
}) {
  return (
    <div className={`card metric disc-metric${tone ? ` disc-metric-${tone}` : ""}`}>
      <div className="lbl">{label}</div>
      <div className="row tile">
        <span className={`value${tone === "warn" ? " warn" : tone === "danger" ? " danger" : ""}`}>{value}</span>
        {qual && <span className="qual">{qual}</span>}
      </div>
      {foot && <div className="foot">{foot}</div>}
    </div>
  );
}

export function Panel({ title, aside, children, className = "" }: { title: string; aside?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <div className={`card section disc-panel ${className}`}>
      <div className="card-head">
        <span className="lbl">{title}</span>
        {aside && <span className="aside">{aside}</span>}
      </div>
      {children}
    </div>
  );
}

// A data gap, stated where the missing thing would have been.
export function Gap({ children }: { children: ReactNode }) {
  return <div className="not-measured">{children}</div>;
}

// Query states in one shape, so every panel loads, fails and empties alike.
export function QueryState({ loading, error, what }: { loading: boolean; error: unknown; what: string }) {
  if (error) return <p className="error">Could not load {what}.</p>;
  if (loading) return <p className="muted">Loading…</p>;
  return null;
}

// An asset as Discover names it: hostname, else current address, else its id —
// with the reason the id is showing when that is the case. Drill-down is the
// existing Asset Detail page; Discover has no detail view of its own. The
// per-row "no current address" note is opt-in: when no row has an address, a
// page says so once rather than on every line.
export function AssetRef({ a, note = false }: { a: { id?: string; asset_id?: string; hostname?: string | null; address?: string | null }; note?: boolean }) {
  const id = a.id ?? a.asset_id ?? "";
  return (
    <>
      <Link to={`/assets/${id}`} className="data">{assetLabel(a)}</Link>
      {note && !a.hostname && !a.address && <span className="faint small"> · no current address</span>}
    </>
  );
}

// The three port states as a donut, from any rows already classified.
export function PortStateDonut({ states, caption }: { states: PortState[]; caption?: string }) {
  const segments = PORT_STATE_ORDER.map((k) => ({
    key: k, label: PORT_STATES[k].label, tone: PORT_STATES[k].tone, value: states.filter((s) => s === k).length,
  }));
  return <Donut segments={segments} center="open ports" caption={caption} />;
}

export function PortStateChip({ state }: { state: PortState }) {
  const s = PORT_STATES[state];
  const chip = s.tone === "ok" ? "ok" : s.tone === "warn" ? "warn" : "muted";
  return <span className={`chip chip-${chip}`} title={s.why}>{s.label}</span>;
}

// Wraps a table so a narrow screen scrolls the TABLE, never the page.
export function TableWrap({ children }: { children: ReactNode }) {
  return <div className="table-wrap">{children}</div>;
}

// Client-side paging over rows the page already holds. Says which slice is
// showing out of how many, so a page never reads as the whole set.
export const PAGE_ROWS = 25;
export function Pager({ page, total, onPage, rows = PAGE_ROWS }: { page: number; total: number; onPage: (p: number) => void; rows?: number }) {
  const pages = Math.max(1, Math.ceil(total / rows));
  if (total <= rows) return <span className="pager-count">{total} {total === 1 ? "row" : "rows"}</span>;
  return (
    <span className="pager">
      <span className="pager-count">{page * rows + 1}–{Math.min(total, (page + 1) * rows)} of {total}</span>
      <button type="button" className="filt" disabled={page === 0} onClick={() => onPage(page - 1)} aria-label="Previous page">‹</button>
      <button type="button" className="filt" disabled={page >= pages - 1} onClick={() => onPage(page + 1)} aria-label="Next page">›</button>
    </span>
  );
}
