import type { ReactNode } from "react";

// Every console surface opens the same way: the title, one sentence that says
// what the numbers below can and cannot claim, and quiet meta on the right.
// The sentence is part of the design, not a caption — rung 1 lives there.
export function PageHead({ title, sub, meta, action }: { title: string; sub?: ReactNode; meta?: ReactNode; action?: ReactNode }) {
  return (
    <div className="page-head">
      <div>
        <h1>{title}</h1>
        {sub && <div className="sub">{sub}</div>}
      </div>
      {action ?? (meta && <div className="meta">{meta}</div>)}
    </div>
  );
}
