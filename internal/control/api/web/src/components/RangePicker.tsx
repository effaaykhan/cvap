import { useEffect, useId, useRef, useState, type KeyboardEvent } from "react";
import { CategoryIcon } from "./CategoryIcon";

// The period selector. A native <select> draws its popup with the platform's
// colours — a white list over the dark theme — so this is a listbox on the
// console's own tokens: trigger, popup, options, hover, selection and focus all
// follow the light and dark themes. Keyboard: Enter/Space/ArrowDown opens,
// arrows and Home/End move, Enter selects, Escape or Tab closes.
export type RangeOption = { key: string; label: string; disabled?: boolean };

export function RangePicker({ options, value, onChange, label = "Time range" }: {
  options: readonly RangeOption[]; value: string; onChange: (key: string) => void; label?: string;
}) {
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(() => Math.max(0, options.findIndex((o) => o.key === value)));
  const root = useRef<HTMLDivElement>(null);
  const list = useRef<HTMLUListElement>(null);
  const trigger = useRef<HTMLButtonElement>(null);
  const id = useId();
  const current = options.find((o) => o.key === value) ?? options[0];

  useEffect(() => {
    if (!open) return;
    list.current?.focus();
    const away = (e: MouseEvent) => { if (!root.current?.contains(e.target as Node)) setOpen(false); };
    document.addEventListener("mousedown", away);
    return () => document.removeEventListener("mousedown", away);
  }, [open]);

  const show = () => {
    setActive(Math.max(0, options.findIndex((o) => o.key === value)));
    setOpen(true);
  };
  const close = (refocus = true) => {
    setOpen(false);
    if (refocus) trigger.current?.focus();
  };
  const choose = (i: number) => {
    const o = options[i];
    if (!o || o.disabled) return;
    onChange(o.key);
    close();
  };
  // The next enabled option from i in direction d, staying put at the ends.
  const step = (i: number, d: number) => {
    for (let j = i + d; j >= 0 && j < options.length; j += d) if (!options[j].disabled) return j;
    return i;
  };
  const onListKey = (e: KeyboardEvent) => {
    if (e.key === "ArrowDown") { e.preventDefault(); setActive((i) => step(i, 1)); }
    else if (e.key === "ArrowUp") { e.preventDefault(); setActive((i) => step(i, -1)); }
    else if (e.key === "Home") { e.preventDefault(); setActive(step(-1, 1)); }
    else if (e.key === "End") { e.preventDefault(); setActive(step(options.length, -1)); }
    else if (e.key === "Enter" || e.key === " ") { e.preventDefault(); choose(active); }
    else if (e.key === "Escape") { e.preventDefault(); close(); }
    else if (e.key === "Tab") close(false);
  };

  return (
    <div className="range-picker" ref={root}>
      <button type="button" ref={trigger} className="range-trigger" aria-haspopup="listbox" aria-expanded={open}
              aria-label={`${label}: ${current.label}`} onClick={() => (open ? close() : show())}
              onKeyDown={(e) => { if (!open && (e.key === "ArrowDown" || e.key === "ArrowUp")) { e.preventDefault(); show(); } }}>
        <CategoryIcon name="calendar" size={16} />
        <span className="range-value">{current.label}</span>
        <svg className="range-chevron" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"
             strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d="m6 9 6 6 6-6" /></svg>
      </button>
      {open && (
        <ul className="range-list" role="listbox" ref={list} tabIndex={-1} aria-label={label}
            aria-activedescendant={`${id}-${active}`} onKeyDown={onListKey}>
          {options.map((o, i) => (
            <li key={o.key} id={`${id}-${i}`} role="option" aria-selected={o.key === value} aria-disabled={o.disabled || undefined}
                className={`range-option${i === active ? " active" : ""}`}
                onMouseEnter={() => !o.disabled && setActive(i)} onClick={() => choose(i)}>
              <span>{o.label}</span>
              {o.key === value && (
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.4" strokeLinecap="round"
                     strokeLinejoin="round" aria-hidden="true"><path d="M20 6 9 17l-5-5" /></svg>
              )}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
