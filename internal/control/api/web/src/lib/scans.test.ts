import { describe, expect, it } from "vitest";
import { countLabel, elapsedLabel, emptyResultMessage, filterScans, killsFor, newestFirst, portList, requesterFull, requesterLabel, summarizeResults } from "./scans";
import type { Scan } from "./api";

const scan = (id: string, extra: Partial<Scan> = {}): Scan => ({
  id, policy_id: "p1", scan_type: "discovery", status: "pending", safety_mode: "safe",
  created_at: "2026-10-08T10:00:00Z", ...extra,
});

describe("Running Scans helpers", () => {
  it("names the requester as You, system, or a short id — never a made-up name", () => {
    expect(requesterLabel(undefined, "u1")).toBe("system");
    expect(requesterLabel("u1", "u1")).toBe("You");
    expect(requesterLabel("1c9e4a77-0000-4000-8000-000000000000", "u1")).toBe("1c9e4a77");
  });

  it("says Waiting from the request while pending or planning, Running from the start", () => {
    const now = new Date("2026-10-08T10:39:00Z").getTime();
    expect(elapsedLabel(scan("a"), now)).toBe("Waiting 39m");
    expect(elapsedLabel(scan("a", { status: "planning" }), now)).toBe("Waiting 39m");
    expect(elapsedLabel(scan("a", { status: "running", started_at: "2026-10-08T10:30:00Z" }), now)).toBe("Running 9m");
  });

  it("calls a count exact only when the server returned no further page", () => {
    expect(countLabel(undefined)).toBe("—");
    expect(countLabel({ scans: [scan("a"), scan("b")] })).toBe("2");
    expect(countLabel({ scans: [scan("a"), scan("b")], next_before: "x", next_id: "b" })).toBe("2+");
  });

  it("filters by status, type, policy and requester together", () => {
    const rows = [
      scan("a", { status: "running", scan_type: "fingerprint", requested_by: "u1" }),
      scan("b", { status: "pending", policy_id: "p2" }),
      scan("c", { status: "running", requested_by: "u2" }),
    ];
    const f = { status: "" as const, type: "", policy: "", mine: false };
    expect(filterScans(rows, f, "u1").map((s) => s.id)).toEqual(["a", "b", "c"]);
    expect(filterScans(rows, { ...f, status: "running" }, "u1").map((s) => s.id)).toEqual(["a", "c"]);
    expect(filterScans(rows, { ...f, type: "fingerprint" }, "u1").map((s) => s.id)).toEqual(["a"]);
    expect(filterScans(rows, { ...f, policy: "p2" }, "u1").map((s) => s.id)).toEqual(["b"]);
    expect(filterScans(rows, { ...f, mine: true }, "u1").map((s) => s.id)).toEqual(["a"]);
    // No session id: "mine" matches nothing rather than every system scan.
    expect(filterScans(rows, { ...f, mine: true }, undefined)).toEqual([]);
  });

  it("orders the merged reads newest request first", () => {
    const rows = [scan("old", { created_at: "2026-10-08T09:00:00Z" }), scan("new", { created_at: "2026-10-08T11:00:00+05:30" }), scan("mid", { created_at: "2026-10-08T05:00:00Z" })];
    expect(newestFirst(rows).map((s) => s.id)).toEqual(["old", "new", "mid"]);
  });
});

describe("View drawer helpers", () => {
  const row = (address: string, port: number, observed_at = "", protocol = "tcp") => ({ address, port, protocol, observed_at });

  it("summarises returned rows without de-duplicating, grouping every row before the host limit", () => {
    const rows = [row("10.0.0.2", 80), row("10.0.0.1", 443), row("10.0.0.1", 22), row("10.0.0.1", 22), row("10.0.0.3", 25)];
    const s = summarizeResults({ ports: rows, hosts: 3, truncated: false }, 2);
    expect(s.hosts).toBe("3");
    expect(s.observations).toBe("5");
    expect(s.groups.map(([a]) => a)).toEqual(["10.0.0.2", "10.0.0.1", "10.0.0.3"]);
    expect(s.shown.map(([a]) => a)).toEqual(["10.0.0.2", "10.0.0.1"]);
    expect(s.more).toBe(1);
    expect(portList(s.groups[1][1])).toBe("22/TCP, 22/TCP, 443/TCP");
  });

  it("appends + to both counts when the server truncated", () => {
    const s = summarizeResults({ ports: [row("10.0.0.1", 22)], hosts: 1, truncated: true });
    expect([s.hosts, s.observations]).toEqual(["1+", "1+"]);
  });

  it("takes the latest valid observed_at and never invents one", () => {
    const valid = summarizeResults({ ports: [row("a", 1, "2026-10-08T10:00:00Z"), row("a", 2, "2026-10-08T11:00:00Z"), row("a", 3, "bad")], hosts: 1, truncated: false });
    expect(valid.latest).toBe("2026-10-08T11:00:00Z");
    expect(summarizeResults({ ports: [row("a", 1, ""), row("a", 2, "bad")], hosts: 1, truncated: false }).latest).toBeNull();
    expect(summarizeResults({ ports: [], hosts: 0, truncated: false }).latest).toBeNull();
  });

  it("chooses the empty-results message from scan type, then status", () => {
    for (const t of ["fingerprint", "rules", "host"]) {
      expect(emptyResultMessage({ scan_type: t, status: "running" })).toBe("This scan type records no open-port observations.");
    }
    for (const st of ["pending", "planning", "running"]) {
      expect(emptyResultMessage({ scan_type: "discovery", status: st })).toBe("Nothing observed yet; results appear once accepted by ingest.");
    }
    for (const st of ["completed", "failed", "cancelled", "killed"]) {
      expect(emptyResultMessage({ scan_type: "discovery", status: st })).toBe("No open-port observations remain (none recorded, or aged out).");
    }
  });

  it("matches kill switches by scan id or tenant scope, never zone", () => {
    const kills = [
      { id: "a", scope: "scan", scan_id: "s1" }, { id: "b", scope: "scan", scan_id: "s2" },
      { id: "c", scope: "zone", zone_id: "z" }, { id: "d", scope: "tenant" },
    ];
    expect(killsFor("s1", kills).map((k) => k.id)).toEqual(["a", "d"]);
  });

  it("shows the full requester id in the drawer, You for the session, system for none", () => {
    const id = "1c9e4a77-0000-4000-8000-000000000000";
    expect(requesterFull(id, "u1")).toBe(id);
    expect(requesterFull("u1", "u1")).toBe("You");
    expect(requesterFull(undefined, "u1")).toBe("system");
  });
});

