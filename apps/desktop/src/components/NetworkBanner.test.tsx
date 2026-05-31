import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";

import { NetworkBanner } from "./NetworkBanner";

// i18n is initialized by src/test/setup.ts before these render.
describe("NetworkBanner (§22.4)", () => {
  it("shows the MAINNET label on a red fill for mainnet ('bitcoin')", () => {
    render(<NetworkBanner network="bitcoin" />);
    const banner = screen.getByRole("status");
    expect(banner).toHaveTextContent("MAINNET");
    expect(banner).toHaveClass("bg-network-mainnet");
  });

  it("colors testnet and signet yellow and regtest gray with matching labels", () => {
    const { rerender } = render(<NetworkBanner network="testnet" />);
    expect(screen.getByRole("status")).toHaveTextContent("TESTNET");
    expect(screen.getByRole("status")).toHaveClass("bg-network-testnet");

    rerender(<NetworkBanner network="signet" />);
    expect(screen.getByRole("status")).toHaveTextContent("SIGNET");
    expect(screen.getByRole("status")).toHaveClass("bg-network-signet");

    rerender(<NetworkBanner network="regtest" />);
    expect(screen.getByRole("status")).toHaveTextContent("REGTEST");
    expect(screen.getByRole("status")).toHaveClass("bg-network-regtest");
  });

  it("recolors instantly when the network prop changes (§22.4)", () => {
    const { rerender } = render(<NetworkBanner network="bitcoin" />);
    expect(screen.getByRole("status")).toHaveClass("bg-network-mainnet");

    rerender(<NetworkBanner network="testnet" />);
    const banner = screen.getByRole("status");
    expect(banner).toHaveClass("bg-network-testnet");
    expect(banner).not.toHaveClass("bg-network-mainnet");
  });

  it("is not dismissible (no close control)", () => {
    render(<NetworkBanner network="bitcoin" />);
    expect(screen.queryByRole("button")).toBeNull();
  });
});
