import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { api, has, type IdentityQueueGroup } from "../lib/api";
import { useAuth } from "../lib/auth";
import { ago, fmtTime } from "../lib/console";

// The identity resolution queue (ADR-007, ADR-094, ADR-096, ADR-097; B39).
//
// Everything correlation parked for a human: an address where the evidence
// contradicts what the asset holds, or two hosts answered on one port. The two
// verbs record a decision and who took it. They verify nothing — on banner
// data nothing can (B44) — and the screen says so beside the buttons, because
// an operator who confirms a key an attacker rotated in has handed that
// attacker the credentialed dial.

export function Identity() {
  const { session } = useAuth();
  const canResolve = has(session, "identity.resolve");
  const qc = useQueryClient();
  const [only, setOnly] = useState("");
  const { data, isLoading, error } = useQuery({ queryKey: ["identity-queue", only], queryFn: () => api.identityQueue(only) });
  const [reason, setReason] = useState<Record<string, string>>({});
  const [outcome, setOutcome] = useState<Record<string, string>>({});

  const resolve = useMutation({
    mutationFn: (v: { address: string; decision: "same_host" | "different_host" | "discard"; asset_id?: string; key_choices?: { key_type: string; source: string; key_value: string }[]; reason: string; seen_through: string }) =>
      api.resolveIdentity(v),
    onSuccess: (res, v) => {
      const part = (label: string, xs: string[]) => (xs.length ? ` · ${label} ${xs.join(", ")}` : "");
      const head = v.decision === "discard" ? "Discarded" : `${v.decision === "same_host" ? "Merged into" : "New asset"} ${res.asset_id.slice(0, 8)}`;
      const recorded = res.keys_recorded.length ? part("recorded", res.keys_recorded) : v.decision === "discard" ? "" : " · recorded nothing";
      setOutcome((o) => ({ ...o, [v.address]: `${head} · ${res.items_closed} item${res.items_closed === 1 ? "" : "s"} closed${recorded}${part("retired", res.keys_retired)}${part("discarded", res.keys_discarded)}${part("left on another asset", res.keys_held_elsewhere)}` }));
      void qc.invalidateQueries({ queryKey: ["identity-queue"] });
      void qc.invalidateQueries({ queryKey: ["health"] });
    },
    onError: (e: Error, v) => setOutcome((o) => ({ ...o, [v.address]: e.message })),
  });

  if (isLoading) return <p className="muted">Loading the queue…</p>;
  if (error) return <p className="error">{(error as Error).message}</p>;
  const groups = data?.groups ?? [];

  return (
    <section className="detail">
      <h1>Identity</h1>
      <p className="muted">
        Addresses where the evidence contradicts what the system holds, parked for a decision. A decision here
        records who made it and re-roots what the credentialed engine will trust; it verifies nothing — an observed
        SSH host key is an echo until the probe checks possession (B44).
      </p>
      <p className="row small" style={{ gap: 8, alignItems: "center" }}>
        <span>{data?.addresses_total ?? 0} contested address{(data?.addresses_total ?? 0) === 1 ? "" : "es"}{(data?.addresses_total ?? 0) > groups.length ? ` · showing the newest ${groups.length}` : ""}</span>
        <input placeholder="Find an address" value={only} onChange={(e) => setOnly(e.target.value.trim())} style={{ minWidth: 200 }} />
      </p>
      {groups.length === 0 ? (
        <p className="muted">{only ? "Nothing is contested at that address." : "Nothing is contested."}</p>
      ) : (
        groups.map((g) => (
          <QueueGroup key={g.address} g={g} canResolve={canResolve}
            reason={reason[g.address] ?? ""} setReason={(v) => setReason((r) => ({ ...r, [g.address]: v }))}
            outcome={outcome[g.address]} busy={resolve.isPending}
            onResolve={(decision, asset_id, key_choices) => resolve.mutate({ address: g.address, decision, asset_id, key_choices, reason: reason[g.address] ?? "", seen_through: g.last_seen })} />
        ))
      )}
    </section>
  );
}

function QueueGroup({ g, canResolve, reason, setReason, outcome, busy, onResolve }: {
  g: IdentityQueueGroup; canResolve: boolean; reason: string; setReason: (v: string) => void;
  outcome?: string; busy: boolean; onResolve: (d: "same_host" | "different_host" | "discard", asset_id?: string, key_choices?: { key_type: string; source: string; key_value: string }[]) => void;
}) {
  // More keys than the page renders: a decision covers exactly what is shown,
  // so the only verb left is discard.
  const tooMany = g.keys_total > g.keys.length;
  // One choice per ambiguous service (two hosts answered on one port), from
  // the server's view over ALL items — not the fifty rendered here.
  const [chosen, setChosen] = useState<Record<string, string>>({});
  const keyed = g.items.filter((i) => i.key_type !== "ip_window");
  const keyless = g.items.length - keyed.length;
  const ambiguous = g.ambiguous.length > 0;
  const allChosen = g.ambiguous.every((a) => !!chosen[`${a.key_type}|${a.source}`]);
  // The service travels with the choice: one fingerprint can be parked on two
  // ports, and a value alone was measured binding to the wrong one.
  const choices = g.ambiguous.filter((a) => !!chosen[`${a.key_type}|${a.source}`])
    .map((a) => ({ key_type: a.key_type, source: a.source, key_value: chosen[`${a.key_type}|${a.source}`] }));
  return (
    <div className="card" style={{ marginBottom: 16 }}>
      <h2 className="data">{g.address} <span className="faint small">contested since {fmtTime(g.first_seen)} · last {ago(g.last_seen)}</span></h2>
      <p>{g.reason}</p>
      {/* Every distinct parked key, over ALL items at the address: exactly what a decision records. */}
      <table><thead><tr><th>Key</th><th>Service</th><th>Fingerprint</th><th>Items</th><th>First</th><th>Last</th></tr></thead>
        <tbody>{g.keys.map((k) => (
          <tr key={`${k.key_type}|${k.source}|${k.key_value}`}>
            <td>{k.key_type}</td><td className="data">{k.source || "—"}</td><td className="data">{k.key_value}</td>
            <td className="data">{k.items}</td><td className="data">{fmtTime(k.first_seen)}</td><td className="data">{ago(k.last_seen)}</td>
          </tr>
        ))}</tbody></table>
      {tooMany && <p className="small">{g.keys_total - g.keys.length} more parked key{g.keys_total - g.keys.length === 1 ? "" : "s"} than this page can show. A decision covers exactly what it shows, so this address can only be discarded here, or left to expire.</p>}
      {g.held.length > 0 && (
        <p className="small">Currently held on those services: {g.held.map((h) => (
          <span key={`${h.asset_id}|${h.source}|${h.key_value}`} className="data" style={{ marginRight: 12 }}>{h.source} {h.key_value} <span className="faint">({h.asset_id.slice(0, 8)})</span></span>
        ))} <span className="faint">— what "same host" retires.</span></p>
      )}
      {keyed.length > 0 && (
        <details><summary className="small">What the newest {keyed.length} observation{keyed.length === 1 ? "" : "s"} said</summary>
          <table><thead><tr><th>Key</th><th>Service</th><th>What it said</th><th>Fingerprint</th><th>Parked</th></tr></thead>
            <tbody>{keyed.map((i) => (
              <tr key={i.resolution_id}>
                <td>{i.key_type}</td><td className="data">{i.source || "—"}</td><td>{i.evidence || "—"}</td><td className="data">{i.key_value}</td><td className="data">{fmtTime(i.enqueued_at)}</td>
              </tr>
            ))}</tbody></table>
        </details>
      )}
      {g.items_total > g.items.length && <p className="faint small">{g.items_total - g.items.length} older item{g.items_total - g.items.length === 1 ? "" : "s"} not shown in detail; the keys above cover all of them.</p>}
      {keyless > 0 && <p className="faint small">{keyless} keyless observation{keyless === 1 ? "" : "s"} parked with the group.</p>}
      {g.ambiguous_total > g.ambiguous.length && <p className="small">{g.ambiguous_total - g.ambiguous.length} more ambiguous service{g.ambiguous_total - g.ambiguous.length === 1 ? "" : "s"} not shown; only discard can decide this address here.</p>}
      {g.ambiguous.map((a) => (
        <div key={`${a.key_type}|${a.source}`} className="small" style={{ margin: "8px 0" }}>
          Two or more different {a.key_type} keys answered on {a.source} here. Pick the one that is the host; the others close as discarded.{a.values_total > a.values.length ? ` (${a.values_total - a.values.length} more not listed)` : ""}
          {a.values.map((v) => (
            <label key={v} style={{ display: "block", marginLeft: 12 }} className="data">
              <input type="radio" name={`host-${g.address}-${a.key_type}-${a.source}`} checked={chosen[`${a.key_type}|${a.source}`] === v}
                onChange={() => setChosen((c) => ({ ...c, [`${a.key_type}|${a.source}`]: v }))} /> {v}
            </label>
          ))}
        </div>
      ))}
      <p className="small">
        Candidates: {g.candidates.length === 0 ? <span className="muted">none — nothing held the address (two hosts answered on one port)</span>
          : g.candidates.map((c) => <Link key={c} to={`/assets/${c}`} className="data" style={{ marginRight: 8 }}>{c.slice(0, 8)}</Link>)}
      </p>
      {canResolve ? (
        <div className="row" style={{ gap: 8, alignItems: "center", flexWrap: "wrap" }}>
          <input placeholder="Why (recorded with your decision)" value={reason} onChange={(e) => setReason(e.target.value)} style={{ minWidth: 280 }} />
          {g.candidates.map((c) => (
            <button key={c} className="btn small-btn" disabled={busy || !reason || tooMany || (ambiguous && !allChosen)} onClick={() => onResolve("same_host", c, choices)}>
              Same host: merge into {c.slice(0, 8)}
            </button>
          ))}
          <button className="btn small-btn" disabled={busy || !reason || tooMany || (ambiguous && !allChosen)} onClick={() => onResolve("different_host", undefined, choices)}>
            Different host: new asset
          </button>
          <button className="btn small-btn" disabled={busy || !reason} onClick={() => onResolve("discard")}>
            Discard: noise
          </button>
          {outcome && <span className="small">{outcome}</span>}
        </div>
      ) : (
        <p className="faint small">Deciding needs the identity.resolve permission.</p>
      )}
    </div>
  );
}
