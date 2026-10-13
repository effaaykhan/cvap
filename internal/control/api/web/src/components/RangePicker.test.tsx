import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { MemoryRouter, useLocation } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import { RangePicker } from "./RangePicker";
import { HeaderSearch } from "./HeaderSearch";
import { RANGES } from "../lib/dashboard";

function Picker({ onChange = () => {}, options = RANGES }: { onChange?: (k: string) => void; options?: readonly { key: string; label: string; disabled?: boolean }[] }) {
  const [v, setV] = useState("24h");
  return <><RangePicker options={options} value={v} onChange={(k) => { setV(k); onChange(k); }} /><button>elsewhere</button></>;
}
const trigger = () => screen.getByRole("button", { name: /^Time range/ });
const options = () => within(screen.getByRole("listbox")).getAllByRole("option");

describe("RangePicker", () => {
  it("is a themed listbox, not a native select, showing the current period", async () => {
    const user = userEvent.setup();
    const { container } = render(<Picker />);
    expect(container.querySelector("select")).toBeNull();
    expect(trigger()).toHaveAttribute("aria-haspopup", "listbox");
    expect(trigger()).toHaveAttribute("aria-expanded", "false");
    expect(trigger()).toHaveTextContent("Last 24 Hours");
    await user.click(trigger());
    expect(trigger()).toHaveAttribute("aria-expanded", "true");
    expect(options().map((o) => o.textContent)).toEqual(RANGES.map((r) => r.label));
    expect(options().filter((o) => o.getAttribute("aria-selected") === "true").map((o) => o.textContent)).toEqual(["Last 24 Hours"]);
    // Every part carries a class the theme tokens style.
    expect(screen.getByRole("listbox")).toHaveClass("range-list");
    expect(options().every((o) => o.classList.contains("range-option"))).toBe(true);
  });

  it("selects with the mouse, then closes and returns focus to the trigger", async () => {
    const user = userEvent.setup();
    const onChange = vi.fn();
    render(<Picker onChange={onChange} />);
    await user.click(trigger());
    await user.click(options()[4]);
    expect(onChange).toHaveBeenCalledWith("30d");
    expect(screen.queryByRole("listbox")).toBeNull();
    expect(trigger()).toHaveTextContent("Last 30 Days");
    expect(trigger()).toHaveFocus();
  });

  it("works from the keyboard: arrows move, Enter selects, Escape closes without changing", async () => {
    const user = userEvent.setup();
    const onChange = vi.fn();
    render(<Picker onChange={onChange} />);
    trigger().focus();
    await user.keyboard("{ArrowDown}");
    expect(screen.getByRole("listbox")).toHaveFocus();
    await user.keyboard("{ArrowDown}{ArrowDown}");
    expect(options()[2]).toHaveClass("active");
    expect(screen.getByRole("listbox")).toHaveAttribute("aria-activedescendant", options()[2].id);
    await user.keyboard("{Enter}");
    expect(onChange).toHaveBeenLastCalledWith("7d");
    await user.keyboard("{Enter}");
    await user.keyboard("{End}");
    expect(options()[6]).toHaveClass("active");
    await user.keyboard("{Escape}");
    expect(screen.queryByRole("listbox")).toBeNull();
    expect(onChange).toHaveBeenCalledTimes(1);
    expect(trigger()).toHaveFocus();
  });

  it("closes on a click outside", async () => {
    const user = userEvent.setup();
    render(<Picker />);
    await user.click(trigger());
    await user.click(screen.getByRole("button", { name: "elsewhere" }));
    expect(screen.queryByRole("listbox")).toBeNull();
  });

  it("never selects a disabled option and skips it from the keyboard", async () => {
    const user = userEvent.setup();
    const onChange = vi.fn();
    render(<Picker onChange={onChange} options={[{ key: "24h", label: "Last 24 Hours" }, { key: "3d", label: "Last 3 Days", disabled: true }, { key: "7d", label: "Last 7 Days" }]} />);
    await user.click(trigger());
    expect(options()[1]).toHaveAttribute("aria-disabled", "true");
    await user.click(options()[1]);
    expect(onChange).not.toHaveBeenCalled();
    await user.keyboard("{ArrowDown}");
    expect(options()[2]).toHaveClass("active");
  });
});

function Where() {
  const l = useLocation();
  return <output data-testid="where">{l.pathname + l.search}</output>;
}

describe("HeaderSearch", () => {
  it("opens the dashboard search with the trimmed query, and ignores an empty one", async () => {
    const user = userEvent.setup();
    render(<MemoryRouter initialEntries={["/scans"]}><HeaderSearch /><Where /></MemoryRouter>);
    const box = screen.getByRole("searchbox");
    expect(box).toHaveValue("");
    await user.type(box, "   {Enter}");
    expect(screen.getByTestId("where")).toHaveTextContent(/^\/scans$/);
    await user.clear(box);
    await user.type(box, "  CVE-2024-1 {Enter}");
    expect(screen.getByTestId("where")).toHaveTextContent("/dashboard/search?q=CVE-2024-1");
  });

  it("shows the query of the results page it is on, and is empty elsewhere", () => {
    render(<MemoryRouter initialEntries={["/dashboard/search?q=db01"]}><HeaderSearch /></MemoryRouter>);
    expect(screen.getByRole("searchbox")).toHaveValue("db01");
  });
});
