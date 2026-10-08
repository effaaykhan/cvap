import { describe, expect, it } from "vitest";
import { countLabel, elapsedLabel, filterScans, newestFirst, requesterLabel } from "./scans";
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
