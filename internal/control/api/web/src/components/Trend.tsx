import { useId, useState } from "react";
import type { TrendPoint } from "../lib/api";
import { yTicks } from "../lib/console";

// Open findings over time (console rung 5), with the KEV subset as a second
// line on the SAME scale — they share a unit, so one axis, never two. Labelled
// gridlines at round values the series reaches, the change window shaded so
// the deltas on the tiles have a place on the chart, the last point
// emphasised. Hover gives the crosshair and both values; the legend names both
// series with their current values so identity is never colour alone; a table
// view holds the same numbers for anyone who prefers to read them.
const W = 640;
const H = 140;
const PAD_L = 34;
const PAD_R = 10;
const PAD_T = 8;
const PAD_B = 18;

export function Trend({ points, days, windowDays }: { points: TrendPoint[]; days: number; windowDays?: number }) {
  const [hover, setHover] = useState<number | null>(null);
  const [table, setTable] = useState(false);
  const id = useId();
  if (points.length === 0) return <p className="muted small">No days to show yet.</p>;

  const innerW = W - PAD_L - PAD_R;
  const innerH = H - PAD_T - PAD_B;
  const ticks = yTicks(Math.max(...points.map((p) => p.open)));
  const top = ticks[ticks.length - 1] || 1;
  // Scaled to the top gridline, so that line is a real value the axis names
  // rather than the data max; both series share it (trendGeometry's rule).
  const yFor = (v: number) => innerH - (innerH * v) / top;
  const n = points.length;
  const xs = points.map((_, i) => (n === 1 ? innerW / 2 : (i * innerW) / (n - 1)));
  const ys = points.map((p) => yFor(p.open));
  const path = (pick: (p: TrendPoint) => number) => points.map((p, i) => `${i ? "L" : "M"}${xs[i].toFixed(1)},${yFor(pick(p)).toFixed(1)}`).join(" ");
  const openPath = path((p) => p.open);
  const kevPath = path((p) => p.kev);
  const area = `${openPath} L${xs[n - 1].toFixed(1)},${innerH} L${xs[0].toFixed(1)},${innerH} Z`;

  const first = points[0];
  const last = points[points.length - 1];
  const h = hover == null ? null : points[hover];
  const winStart = windowDays && windowDays < points.length ? xs[points.length - windowDays] : null;
  const labelEvery = Math.max(1, Math.round(points.length / 5));

  const onMove = (e: React.MouseEvent<SVGSVGElement>) => {
    const rect = e.currentTarget.getBoundingClientRect();
    const px = ((e.clientX - rect.left) / rect.width) * W - PAD_L;
    let best = 0;
    for (let i = 1; i < xs.length; i++) if (Math.abs(xs[i] - px) < Math.abs(xs[best] - px)) best = i;
    setHover(best);
  };

  return (
    <div className="trend">
      <div className="trend-legend">
        <span className="lane"><span className="swatch swatch-open" />open <span className="val">{last.open}</span></span>
        <span className="lane"><span className="swatch swatch-kev" />in KEV <span className="val">{last.kev}</span></span>
        {windowDays && <span className="lane"><span className="swatch swatch-window" />last {windowDays} days</span>}
        <span className="end">
          {first.day} → {last.day}
          <button className="link" onClick={() => setTable(!table)} aria-expanded={table}>{table ? "hide table" : "table"}</button>
        </span>
      </div>
      <svg viewBox={`0 0 ${W} ${H}`} className="trend-svg" role="img" aria-labelledby={id}
           onMouseMove={onMove} onMouseLeave={() => setHover(null)}>
        <title id={id}>Open findings over {days} days, {first.open} to {last.open}; in KEV {first.kev} to {last.kev}</title>
        <g transform={`translate(${PAD_L},${PAD_T})`}>
          {winStart != null && <rect x={winStart} y={0} width={innerW - winStart} height={innerH} className="trend-window" />}
          {ticks.map((t) => (
            <g key={t}>
              <line x1={0} x2={innerW} y1={yFor(t)} y2={yFor(t)} className="trend-grid" />
              <text x={-6} y={yFor(t) + 3} className="trend-tick" textAnchor="end">{t}</text>
            </g>
          ))}
          <path d={area} className="trend-area" />
          <path d={openPath} className="trend-open" />
          <path d={kevPath} className="trend-kev" />
          <circle cx={xs[xs.length - 1]} cy={ys[ys.length - 1]} r="3.5" className="trend-dot" />
          {hover != null && (
            <>
              <line x1={xs[hover]} x2={xs[hover]} y1={0} y2={innerH} className="trend-cross" />
              <circle cx={xs[hover]} cy={ys[hover]} r="4" className="trend-dot" />
              <circle cx={xs[hover]} cy={yFor(points[hover].kev)} r="3" className="trend-dot-kev" />
            </>
          )}
          {points.map((p, i) => (i % labelEvery === 0 || i === points.length - 1) && (
            <text key={p.day} x={xs[i]} y={innerH + 13} className="trend-tick" textAnchor={i === points.length - 1 ? "end" : i === 0 ? "start" : "middle"}>{p.day.slice(5)}</text>
          ))}
        </g>
      </svg>
      <div className="trend-readout" aria-live="polite">
        {h ? <><span className="data">{h.day}</span> · open <b>{h.open}</b> · in KEV <b>{h.kev}</b></> : <span className="faint">hover for a day · gridlines at {ticks.slice(1).join(", ")}</span>}
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
