import { useId, useState } from "react";
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
            <span className="hbar-label"><span className="data">{r.label}</span>{r.sub && <span className="faint"> {r.sub}</span>}</span>
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
