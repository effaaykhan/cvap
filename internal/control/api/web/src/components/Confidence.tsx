// Confidence is the product's whole argument: a banner-inferred claim and an
// advisory-matched one are not the same, and the UI must not let good design make
// the weak one look authoritative. So confidence is shown as a meter plus its
// value, and a low reading is drawn to LOOK less certain — dimmed, in the
// neutral colour rather than the accent, and labelled "low".
export function Confidence({ value }: { value?: number }) {
  const v = Math.max(0, Math.min(1, value ?? 0));
  const pct = Math.round(v * 100);
  const level = v >= 0.85 ? "high" : v >= 0.6 ? "medium" : "low";
  return (
    <span className={`conf conf-${level}`} title={`confidence ${pct}%`}>
      <span className="conf-track">
        <span className="conf-fill" style={{ width: `${pct}%` }} />
      </span>
      <span className="conf-val">{pct}%</span>
    </span>
  );
}
