import { afterEach, describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import Learn from "./Learn";
import * as commands from "../tauri/commands";

// Learn renders the bundled docs through MarkdownView, whose only IPC dependency
// is open_external_link. Mock that seam so a link click is observable and the
// jsdom suite never touches the real bridge. i18n is initialized in test setup.
vi.mock("../tauri/commands", () => ({
  openExternalLink: vi.fn().mockResolvedValue(undefined),
}));

const mocked = vi.mocked(commands);

describe("Learn docs viewer (§28 / US-055)", () => {
  afterEach(() => {
    vi.clearAllMocks();
  });

  it("shows the overview page first", () => {
    render(<Learn />);
    expect(
      screen.getByRole("heading", { level: 1, name: "What Bitcoin Lifeboat is" }),
    ).toBeInTheDocument();
  });

  it("lists the glossary and the safety page in the nav", () => {
    render(<Learn />);
    expect(screen.getByRole("button", { name: "Glossary" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Staying safe" })).toBeInTheDocument();
  });

  it("opens the glossary when its nav item is selected", async () => {
    const user = userEvent.setup();
    render(<Learn />);

    await user.click(screen.getByRole("button", { name: "Glossary" }));

    expect(screen.getByText(/Plain-English definitions/i)).toBeInTheDocument();
  });

  it("opens the safety education page when its nav item is selected", async () => {
    const user = userEvent.setup();
    render(<Learn />);

    await user.click(screen.getByRole("button", { name: "Staying safe" }));

    expect(
      screen.getByRole("heading", { name: "Never enter your seed phrase online" }),
    ).toBeInTheDocument();
  });

  it("routes an external doc link through the allowlisted open_external_link command", async () => {
    const user = userEvent.setup();
    render(<Learn />);

    await user.click(screen.getByRole("link", { name: /bitcoinlifeboat\.org\/docs/ }));

    expect(mocked.openExternalLink).toHaveBeenCalledWith("https://bitcoinlifeboat.org/docs/");
  });

  it("follows an in-doc cross-link in-app, without opening the browser", async () => {
    const user = userEvent.setup();
    render(<Learn />);

    await user.click(screen.getByRole("link", { name: "glossary" }));

    expect(screen.getByText(/Plain-English definitions/i)).toBeInTheDocument();
    expect(mocked.openExternalLink).not.toHaveBeenCalled();
  });
});
