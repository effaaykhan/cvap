import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { EvidenceBlock } from "./Evidence";
import type { Evidence } from "../lib/api";

describe("EvidenceBlock (the deliverable: verify by hand)", () => {
  it("renders the observed values a human checks", () => {
    const ev: Evidence[] = [{
      type: "response",
      data: { not_after: "2026-01-02T00:00:00Z", subject: "CN=expired.example", legacy_versions: ["TLSv1.0", "TLSv1.1"] },
      observation_id: "obs-1",
      observation_aged_out: false,
      has_full_artefact: false,
      captured_at: "2026-09-05T00:00:00Z",
    }];
    render(<EvidenceBlock evidence={ev} />);
    expect(screen.getByText("not_after")).toBeInTheDocument();
    expect(screen.getByText("2026-01-02T00:00:00Z")).toBeInTheDocument();
    // A set-matched value renders its members.
    expect(screen.getByText("TLSv1.0, TLSv1.1")).toBeInTheDocument();
    expect(screen.getByText(/observation obs-1/)).toBeInTheDocument();
  });

  it("says an aged-out observation honestly, with no dead link", () => {
    const ev: Evidence[] = [{
      type: "response",
      data: { key_bits: 1024 },
      observation_aged_out: true,
      has_full_artefact: false,
      captured_at: "2026-09-05T00:00:00Z",
    }];
    render(<EvidenceBlock evidence={ev} />);
    expect(screen.getByText(/aged out/i)).toBeInTheDocument();
    // The evidence itself survives.
    expect(screen.getByText("key_bits")).toBeInTheDocument();
    // No zero-uuid or bare "observation <id>" dead link.
    expect(screen.queryByText(/observation obs/)).toBeNull();
  });
});
