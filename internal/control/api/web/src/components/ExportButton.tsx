import { useAuth } from "../lib/auth";
import { has } from "../lib/api";

// ExportButton degrades HONESTLY (constraint 2, ADR-052): a caller without the
// export permission still SEES the control, disabled, with the reason named —
// the UI never pretends the option does not exist. The server holds the real
// gate (the route requires the permission); this only reflects it. When
// permitted it is a plain download link.
export function ExportButton({ perm, href }: { perm: string; href: string }) {
  const { session } = useAuth();
  if (has(session, perm)) {
    return (
      <a className="btn" href={href} download>
        Export CSV
      </a>
    );
  }
  return (
    <span
      className="btn disabled"
      aria-disabled="true"
      title={`Requires the ${perm} permission, which this account does not hold.`}
    >
      Export CSV — requires {perm}
    </span>
  );
}
