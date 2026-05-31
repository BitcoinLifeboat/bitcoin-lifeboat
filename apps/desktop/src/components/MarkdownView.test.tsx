import { afterEach, describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import { MarkdownView } from "./MarkdownView";
import * as commands from "../tauri/commands";

// MarkdownView is the only seam that can open an external link from the docs, so
// mock the IPC client and assert routing happens through it (never a raw webview
// navigation). i18n is not needed here — MarkdownView renders raw Markdown.
vi.mock("../tauri/commands", () => ({
  openExternalLink: vi.fn().mockResolvedValue(undefined),
}));

const mocked = vi.mocked(commands);

describe("MarkdownView (§28.4 / US-055)", () => {
  afterEach(() => {
    vi.clearAllMocks();
  });

  it("renders standard Markdown elements", () => {
    const { container } = render(<MarkdownView content={"# Title\n\nSome **bold** text."} />);
    expect(container.querySelector("h1")?.textContent).toBe("Title");
    expect(container.querySelector("strong")?.textContent).toBe("bold");
  });

  it("forbids raw HTML: tags in the source are escaped, never rendered as DOM", () => {
    const { container } = render(
      <MarkdownView content={"A line with <script>alert(1)</script> and a <b>tag</b>."} />,
    );
    // No live elements were created from the raw markup...
    expect(container.querySelector("script")).toBeNull();
    expect(container.querySelector("b")).toBeNull();
    // ...the markup survives only as inert, escaped text.
    expect(container.textContent).toContain("<script>alert(1)</script>");
    expect(container.textContent).toContain("<b>tag</b>");
  });

  it("opens an external https link through the allowlisted command, not the webview", async () => {
    const user = userEvent.setup();
    render(<MarkdownView content={"[docs](https://bitcoinlifeboat.org/docs/)"} />);

    await user.click(screen.getByRole("link", { name: "docs" }));

    expect(mocked.openExternalLink).toHaveBeenCalledWith("https://bitcoinlifeboat.org/docs/");
  });

  it("handles an intra-doc link via onNavigate, without opening the browser", async () => {
    const onNavigate = vi.fn();
    const user = userEvent.setup();
    render(<MarkdownView content={"[see glossary](glossary)"} onNavigate={onNavigate} />);

    await user.click(screen.getByRole("link", { name: "see glossary" }));

    expect(onNavigate).toHaveBeenCalledWith("glossary");
    expect(mocked.openExternalLink).not.toHaveBeenCalled();
  });

  it("normalizes a relative `.md` link to a bare doc id", async () => {
    const onNavigate = vi.fn();
    const user = userEvent.setup();
    render(<MarkdownView content={"[d](./descriptors.md)"} onNavigate={onNavigate} />);

    await user.click(screen.getByRole("link", { name: "d" }));

    expect(onNavigate).toHaveBeenCalledWith("descriptors");
  });
});
