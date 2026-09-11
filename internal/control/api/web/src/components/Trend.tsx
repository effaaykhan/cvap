import { useId, useState } from "react";
import type { TrendPoint } from "../lib/api";
import { trendGeometry } from "../lib/console";

// Open findings over time (console rung 5), with the KEV subset as a second
// line on the SAME scale — they share a unit, so one axis. A count with no
// history says nothing about whether you are winning; this is the history.
//
// Hover gives the crosshair and the day's two values; the legend names both
// series and each carries its current value at the line's end, so identity is
// never colour alone; a table view holds the same numbers for anyone who
// prefers to read them.
const W = 640;
const H = 96;

export function Trend({ points, days }: { points: TrendPoint[]; days: number }) {
  const [hover, setHover] = useState<number | null>(null);
  const [table, setTable] = useState(false);
  const id = useId();
  const g = trendGeometry(points, W, H);
  const last = points[points.length - 1];
  const first = points[0];

  if (points.length === 0) return <p className="muted small">No days to show yet.</p>;

  const onMove = (e: React.MouseEvent<SVGSVGElement>) => {
    const rect = e.currentTarget.getBoundingClientRect();
    const px = ((e.clientX - rect.left) / rect.width) * W;
    let best = 0;
    for (let i = 1; i < g.xs.length; i++) if (Math.abs(g.xs[i] - px) < Math.abs(g.xs[best] - px)) best = i;
    setHover(best);
  };
  const h = hover == null ? null : points[hover];

  return (
    <div className="trend">
      <div className="trend-legend">
        <span className="lane"><span className="swatch swatch-open" />open <span className="val">{last.open}</span></span>
        <span className="lane"><span className="swatch swatch-kev" />in KEV <span className="val">{last.kev}</span></span>
        <span className="end">
          {days} days · {first.day} → {last.day}
          <button className="link" onClick={() => setTable(!table)} aria-expanded={table}>{table ? "hide table" : "table"}</button>
        </span>
      </div>
      <svg viewBox={`0 0 ${W} ${H}`} className="trend-svg" role="img" aria-labelledby={id}
           onMouseMove={onMove} onMouseLeave={() => setHover(null)}>
        <title id={id}>Open findings over {days} days, {first.open} to {last.open}; in KEV {first.kev} to {last.kev}</title>
        <line x1="0" x2={W} y1={H - 4} y2={H - 4} className="trend-grid" />
        <line x1="0" x2={W} y1={4} y2={4} className="trend-grid" />
        <path d={g.area} className="trend-area" />
        <path d={g.open} className="trend-open" />
        <path d={g.kev} className="trend-kev" />
        {hover != null && (
          <>
            <line x1={g.xs[hover]} x2={g.xs[hover]} y1={0} y2={H} className="trend-cross" />
            <circle cx={g.xs[hover]} cy={g.ys[hover]} r="4" className="trend-dot" />
          </>
        )}
        <text x={W - 4} y={12} className="trend-max" textAnchor="end">{g.max}</text>
      </svg>
      <div className="trend-readout" aria-live="polite">
        {h ? <><span className="data">{h.day}</span> · open <b>{h.open}</b> · in KEV <b>{h.kev}</b></> : <span className="faint">hover for a day</span>}
      </div>
      {table && (
        <div className="trend-table">
          <table>
            <thead><tr><th>Day</th><th className="num">Open</th><th className="num">In KEV</th></tr></thead>
            <tbody>
              {points.map((p) => (
                <tr key={p.day}><td className="data">{p.day}</td><td className="num">{p.open}</td><td className="num">{p.kev}</td></tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
