import { describe, expect, it, vi } from "vitest";
import type { AssetList } from "./api";
import { assetLabel, dbEngineForPort, duration, fetchAllAssets, perDay, portState, recency, serviceState, topN } from "./discovery";

const page = (ids: string[], next?: { before: string; id: string }): AssetList =>
  ({
    assets: ids.map((id) => ({ id, first_seen: "2026-09-23T10:00:00Z", last_seen: "2026-09-25T10:00:00Z" })),
    address_presence: { present: 0, responder: 0, unknown: 0, total: 0, statement: "" },
    next_before: next?.before,
    next_id: next?.id,
  }) as unknown as AssetList;

describe("discovery helpers", () => {
  it("walks the asset cursor to the end and reports completeness", async () => {
    const list = vi.fn()
      .mockResolvedValueOnce(page(["a", "b"], { before: "2026-09-25T10:00:00Z", id: "b" }))
      .mockResolvedValueOnce(page(["c"]));
    const out = await fetchAllAssets(list);
    expect(out.assets.map((a) => a.id)).toEqual(["a", "b", "c"]);
    expect(out.complete).toBe(true);
    expect(list.mock.calls[1][0]).toContain("before_id=b");
  });

  it("stops at the cap and says the count is not the total", async () => {
    const list = vi.fn().mockResolvedValue(page(["x", "y"], { before: "2026-09-25T10:00:00Z", id: "y" }));
    const out = await fetchAllAssets(list, 3);
    expect(out.complete).toBe(false);
    expect(list).toHaveBeenCalledTimes(2);
  });

  it("splits ports into recognised, probed-no-match and seen-only", () => {
    expect(portState({ identified: false, service: undefined })).toBe("answered");
    expect(portState({ identified: true, service: undefined })).toBe("probed");
    expect(portState({ identified: true, service: "ssh" })).toBe("recognised");
    expect(serviceState({ method: "discovery" })).toBe("answered");
    expect(serviceState({ method: "none" })).toBe("probed");
    expect(serviceState({ method: "banner", service: "mysql" })).toBe("recognised");
  });

  it("names an asset by hostname, then address, then id", () => {
    expect(assetLabel({ id: "0123456789", hostname: "db1", address: "10.0.0.1" })).toBe("db1");
    expect(assetLabel({ id: "0123456789", address: "10.0.0.1" })).toBe("10.0.0.1");
    expect(assetLabel({ asset_id: "0123456789" })).toBe("01234567");
  });

  it("maps only the database engines Core identifies", () => {
    expect(dbEngineForPort(3306)).toBe("mysql");
    expect(dbEngineForPort(5432)).toBe("postgresql");
    expect(dbEngineForPort(1433)).toBe("ms-sql-s");
    expect(dbEngineForPort(1521)).toBeUndefined(); // Oracle: no rule names it
    expect(dbEngineForPort(27017)).toBeUndefined();
  });

  it("fills quiet days with zero bars", () => {
    const days = perDay(["2026-09-20T12:00:00", "2026-09-22T12:00:00", "2026-09-22T13:00:00"]);
    expect(days.map((d) => d.n)).toEqual([1, 0, 2]);
  });

  it("buckets recency and measures durations from server timestamps", () => {
    const now = new Date("2026-10-01T00:00:00Z").getTime();
    expect(recency("2026-09-30T12:00:00Z", now)).toBe("day");
    expect(recency("2026-09-25T00:00:00Z", now)).toBe("week");
    expect(recency("2026-09-10T00:00:00Z", now)).toBe("month");
    expect(recency("2026-07-01T00:00:00Z", now)).toBe("older");
    expect(duration("2026-09-25T07:45:02Z", "2026-09-25T13:27:48Z")).toBe("5h 43m");
    expect(duration(null, null)).toBe("—");
  });

  it("orders a tally largest first with stable ties", () => {
    expect(topN({ "80/tcp": 2, "22/tcp": 2, "443/tcp": 5 }, 2)).toEqual([["443/tcp", 5], ["22/tcp", 2]]);
  });
});
