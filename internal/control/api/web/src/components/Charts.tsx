import { useId, useState } from "react";
import { Link } from "react-router-dom";
import { sparkPath, stackSegments } from "../lib/console";

// Small chart primitives on the console's tokens. Each one: thin marks, a
// legend whenever there is more than one series, a hover readout in text
// tokens (never the series colour), and the numbers themselves beside the
// marks so nothing is colour-alone. All SVG, no library.

export type SegmentSpec = { key: string; label: string; value: number; tone: string; to?: string };

// SegmentBar is a stacked horizontal bar — severity distribution, fleet
// status, scan status — with a 2px surface gap between segments and a legend
// that doubles as the readout.
export function SegmentBar({ segments, height = 10, caption }: { segments: SegmentSpec[]; height?: number; caption?: string }) {
  const [hover, setHover] = useState<string | null>(null);
  const { total, segments: stacked } = stackSegments(segments.map((s) => [s.key, s.value]));
  const byKey = Object.fromEntries(segments.map((s) => [s.key, s]));
  return (
    <div className="segbar">
      <div className="segbar-track" style={{ height }} role="img" aria-label={caption ?? segments.map((s) => `${s.label} ${s.value}`).join(", ")}>
        {stacked.map((s) => (
          <span
            key={s.key}
            className={`segbar-seg tone-${byKey[s.key].tone}${hover && hover !== s.key ? " dim" : ""}`}
            style={{ width: `${s.pct}%` }}
            onMouseEnter={() => setHover(s.key)}
            onMouseLeave={() => setHover(null)}
            title={`${byKey[s.key].label}: ${s.value} (${s.pct.toFixed(0)}%)`}
          />
        ))}
        {total === 0 && <span className="segbar-empty" />}
      </div>
      <div className="segbar-legend">
        {segments.map((s) => (
          <span key={s.key} className={`lane${hover === s.key ? " on" : ""}`} onMouseEnter={() => setHover(s.key)} onMouseLeave={() => setHover(null)}>
            <span className={`cdot tone-${s.tone}`} />{s.label}
            <span className="val">{s.value}</span>
          </span>
        ))}
        {caption && <span className="end">{caption}</span>}
      </div>
    </div>
  );
}

// Sparkline: a tile-sized series with the endpoint emphasised. Single series,
// so no legend; the tile's label names it.
export function Sparkline({ values, tone = "accent", width = 96, height = 28 }: { values: number[]; tone?: string; width?: number; height?: number }) {
  const id = useId();
  const s = sparkPath(values, width, height - 2);
  if (!s.last) return null;
  return (
    <svg viewBox={`0 0 ${width} ${height}`} width={width} height={height} className={`spark tone-${tone}`} role="img" aria-labelledby={id}>
      <title id={id}>{values.length} points, {values[0]} to {values[values.length - 1]}</title>
      <path d={s.area} className="spark-area" transform="translate(0,1)" />
      <path d={s.line} className="spark-line" transform="translate(0,1)" />
      <circle cx={s.last.x} cy={s.last.y + 1} r="2.5" className="spark-dot" />
    </svg>
  );
}

// RatioBar: one quantity against its own limit — feed age against the
// staleness threshold. The 1.0 mark is drawn, the fill is coloured by the
// server's verdict rather than by the ratio, and the raw age travels beside it.
export function RatioBar({ ratio, tone, label }: { ratio: number | null; tone: string; label: string }) {
  const pct = ratio == null ? 0 : Math.min(200, ratio * 100) / 2; // 1.0 sits at the halfway mark
  return (
    <span className="ratiobar" title={label} aria-label={label}>
      <span className="ratiobar-track">
        <span className={`ratiobar-fill tone-${tone}`} style={{ width: `${pct}%` }} />
        <span className="ratiobar-limit" />
      </span>
      <span className="val">{ratio == null ? "—" : `${Math.round(ratio * 100)}%`}</span>
    </span>
  );
}

// HBars: horizontal bars, one row per entity, each stacked by severity —
// exposure by zone. Bars share one scale (the largest row is full width).
export type HBarRow = { key: string; label: string; sub?: string; segments: SegmentSpec[]; to?: string };
export function HBars({ rows, unit = "findings" }: { rows: HBarRow[]; unit?: string }) {
  const max = Math.max(1, ...rows.map((r) => r.segments.reduce((n, s) => n + s.value, 0)));
  return (
    <div className="hbars">
      {rows.map((r) => {
        const total = r.segments.reduce((n, s) => n + s.value, 0);
        const { segments } = stackSegments(r.segments.map((s) => [s.key, s.value]));
        const byKey = Object.fromEntries(r.segments.map((s) => [s.key, s]));
        return (
          <div className="hbar" key={r.key}>
            <span className="hbar-label">{r.to ? <Link className="data" to={r.to}>{r.label}</Link> : <span className="data">{r.label}</span>}{r.sub && <span className="faint"> {r.sub}</span>}</span>
            <span className="hbar-track" role="img" aria-label={`${r.label}: ${total} ${unit}`}>
              <span className="hbar-bar" style={{ width: `${(100 * total) / max}%` }}>
                {segments.map((s) => (
                  <span key={s.key} className={`segbar-seg tone-${byKey[s.key].tone}`} style={{ width: `${s.pct}%` }}
                        title={`${r.label} · ${byKey[s.key].label}: ${s.value}`} />
                ))}
              </span>
            </span>
            <span className="hbar-value">{total}</span>
          </div>
        );
      })}
    </div>
  );
}

// Donut: one whole split into a few named parts — port identification
// states, presence verdicts, database engines. The total sits in the hole and
// the legend carries every number, so the ring is never read alone. A zero
// total draws an empty track and says so rather than a full ring of nothing.
export function Donut({ segments, size = 128, thickness = 14, center, caption }: {
  segments: SegmentSpec[]; size?: number; thickness?: number; center?: string; caption?: string;
}) {
  const [hover, setHover] = useState<string | null>(null);
  const { total, segments: stacked } = stackSegments(segments.map((s) => [s.key, s.value]));
  const byKey = Object.fromEntries(segments.map((s) => [s.key, s]));
  const r = (size - thickness) / 2;
  const c = 2 * Math.PI * r;
  const gap = stacked.length > 1 ? 2 : 0;
  let offset = 0;
  const hovered = hover ? byKey[hover] : null;
  return (
    <div className="donut">
      <svg viewBox={`0 0 ${size} ${size}`} width={size} height={size} role="img"
           aria-label={caption ?? segments.map((s) => `${s.label} ${s.value}`).join(", ")}>
        <circle cx={size / 2} cy={size / 2} r={r} className="donut-track" strokeWidth={thickness} />
        {stacked.map((s) => {
          const len = Math.max(0, (s.pct / 100) * c - gap);
          const el = (
            <circle key={s.key} cx={size / 2} cy={size / 2} r={r}
                    className={`donut-seg tone-${byKey[s.key].tone}${hover && hover !== s.key ? " dim" : ""}`}
                    strokeWidth={thickness} strokeDasharray={`${len} ${c - len}`} strokeDashoffset={-offset}
                    transform={`rotate(-90 ${size / 2} ${size / 2})`}
                    onMouseEnter={() => setHover(s.key)} onMouseLeave={() => setHover(null)}>
              <title>{`${byKey[s.key].label}: ${s.value} (${s.pct.toFixed(0)}%)`}</title>
            </circle>
          );
          offset += (s.pct / 100) * c;
          return el;
        })}
        <text x="50%" y="48%" textAnchor="middle" className="donut-value">{hovered ? hovered.value : total}</text>
        <text x="50%" y="62%" textAnchor="middle" className="donut-caption">{hovered ? hovered.label : center ?? "total"}</text>
      </svg>
      <div className="donut-legend">
        {segments.map((s) => (
          <span key={s.key} className={`lane${hover === s.key ? " on" : ""}`} onMouseEnter={() => setHover(s.key)} onMouseLeave={() => setHover(null)}>
            <span className={`cdot tone-${s.tone}`} />
            <span className="lane-label">{s.label}</span>
            <span className="val">{s.value}</span>
            <span className="pct">{total ? `${Math.round((100 * s.value) / total)}%` : "—"}</span>
          </span>
        ))}
        {caption && <span className="end">{caption}</span>}
      </div>
    </div>
  );
}

// Columns: a count per bucket along one axis — assets first seen per day.
// Bars share a scale whose top is labelled; the bucket labels thin out on a
// long axis so they never overlap, and every bar carries its own readout.
export type Column = { key: string; label: string; value: number };
export function Columns({ data, tone = "accent", height = 120, unit = "" }: { data: Column[]; tone?: string; height?: number; unit?: string }) {
  const [hover, setHover] = useState<number | null>(null);
  const max = Math.max(1, ...data.map((d) => d.value));
  const every = Math.max(1, Math.ceil(data.length / 8));
  const h = hover == null ? null : data[hover];
  return (
    <div className="cols-wrap">
      <div className="cols-readout">{h ? <><span className="val">{h.value}</span> {unit} · {h.label}</> : <span className="faint">max {max} {unit}</span>}</div>
      <div className={`cols tone-${tone}`} style={{ height }} role="img" aria-label={data.map((d) => `${d.label}: ${d.value}`).join(", ")}>
        {data.map((d, i) => (
          <span key={d.key} className={`col${hover != null && hover !== i ? " dim" : ""}`}
                onMouseEnter={() => setHover(i)} onMouseLeave={() => setHover(null)} title={`${d.label}: ${d.value} ${unit}`}>
            <span className="col-bar" style={{ height: d.value > 0 ? `max(2px, ${(100 * d.value) / max}%)` : 0 }} />
          </span>
        ))}
      </div>
      <div className="cols-axis">
        {data.map((d, i) => <span key={d.key} className="col-tick">{i % every === 0 || i === data.length - 1 ? d.label : ""}</span>)}
      </div>
    </div>
  );
}
