import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { beforeEach, describe, expect, it, vi } from "vitest";

const session = { permissions: [] as string[] };
vi.mock("../lib/auth", () => ({ useAuth: () => ({ session }) }));

const settings = {
  default_hours: 72, is_default: true, min_hours: 24, max_hours: 2160,
  scan_cadence_hours: 2.8, scan_cadence_samples: 9, sighting_window_hours: 72,
};
const api = vi.hoisted(() => ({
  identitySettings: vi.fn(),
  setIdentityWindow: vi.fn(),
  listCredentialProfiles: vi.fn(),
  changePassword: vi.fn(),
}));
vi.mock("../lib/api", async (orig) => ({ ...(await orig<typeof import("../lib/api")>()), api }));

import { Settings } from "./Settings";

function renderSettings() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={qc}><Settings /></QueryClientProvider>);
}

describe("Settings", () => {
  beforeEach(() => {
    session.permissions = ["policy.read", "policy.write"];
    vi.clearAllMocks();
    api.identitySettings.mockResolvedValue({ ...settings });
    api.listCredentialProfiles.mockResolvedValue({ profiles: [] });
  });

  it("shows the current window apart from an empty new-window input", async () => {
    renderSettings();
    expect(await screen.findByText("72 hours")).toBeInTheDocument();
    const hours = screen.getByLabelText("Set new window");
    expect(hours).toHaveValue(null);
    expect(hours).toHaveAttribute("placeholder", "Hours");
    expect(screen.getByText(/Allowed range: 24–2160 hours \(1–90 days\)/)).toBeInTheDocument();
    expect(screen.getByText("✓ Compatible")).toBeInTheDocument();
    expect(screen.getByText("No credential profiles configured.")).toBeInTheDocument();
  });

  it("requires a reason, then shows the saved window and clears both inputs", async () => {
    const user = userEvent.setup();
    const saved = { ...settings, is_default: false, sighting_window_hours: 96 };
    api.setIdentityWindow.mockImplementation(async () => {
      api.identitySettings.mockResolvedValue(saved); // the refetch reads what was stored
      return saved;
    });
    renderSettings();
    const hours = await screen.findByLabelText("Set new window");
    const set = screen.getByRole("button", { name: "Set window" });
    await user.type(hours, "96");
    expect(set).toBeDisabled();
    const reason = screen.getByPlaceholderText("Why are you changing this?");
    await user.type(reason, "slower scans");
    await user.click(set);
    expect(api.setIdentityWindow).toHaveBeenCalledWith(96, "slower scans");
    expect(await screen.findByText("96 hours")).toBeInTheDocument();
    expect(hours).toHaveValue(null);
    expect(reason).toHaveValue("");
  });

  it("toggles each password field's visibility independently", async () => {
    const user = userEvent.setup();
    renderSettings();
    const fields = ["Current password", "New password", "Retype new password"].map((l) => screen.getByLabelText(l));
    fields.forEach((f) => expect(f).toHaveAttribute("type", "password"));
    const toggle = within(fields[1].parentElement!).getByRole("button", { name: "Show password" });
    await user.click(toggle);
    expect(fields[1]).toHaveAttribute("type", "text");
    expect(toggle).toHaveAccessibleName("Hide password");
    expect(fields[0]).toHaveAttribute("type", "password");
    expect(fields[2]).toHaveAttribute("type", "password");
    await user.click(toggle);
    expect(fields[1]).toHaveAttribute("type", "password");
  });

  it("keeps the password validation", async () => {
    const user = userEvent.setup();
    renderSettings();
    await user.type(screen.getByLabelText("New password"), "short");
    await user.type(screen.getByLabelText("Retype new password"), "other");
    await user.click(screen.getByRole("button", { name: "Change password" }));
    expect(screen.getByText("The new password and its confirmation do not match.")).toBeInTheDocument();
    expect(api.changePassword).not.toHaveBeenCalled();
  });
});
