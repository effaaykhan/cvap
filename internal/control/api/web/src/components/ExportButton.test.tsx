import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

// Mock the auth hook so the test controls the session's permissions.
const session = { permissions: [] as string[] };
vi.mock("../lib/auth", () => ({ useAuth: () => ({ session }) }));

import { ExportButton } from "./ExportButton";

describe("ExportButton (RBAC reflected, degrades honestly)", () => {
  it("is a real download link when the permission is held", () => {
    session.permissions = ["finding.export_all"];
    render(<ExportButton perm="finding.export_all" href="/v1/findings.csv" />);
    const link = screen.getByText(/export csv/i);
    expect(link).toHaveAttribute("href", "/v1/findings.csv");
    expect(link.getAttribute("aria-disabled")).toBeNull();
  });

  it("is shown, disabled, and names the permission when it is NOT held", () => {
    session.permissions = ["finding.read"]; // read but not export
    render(<ExportButton perm="finding.export_all" href="/v1/findings.csv" />);
    // The option is not hidden — it is present and names why it is unavailable.
    const el = screen.getByText(/finding\.export_all/);
    expect(el).toBeInTheDocument();
    expect(el).toHaveAttribute("aria-disabled", "true");
    expect(el).not.toHaveAttribute("href");
  });
});
