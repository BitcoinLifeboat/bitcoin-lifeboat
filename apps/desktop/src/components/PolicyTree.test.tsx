import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";

import { parsePolicyDot, PolicyTree } from "./PolicyTree";

const MULTISIG_DOT = `digraph miniscript_policy {
  graph [rankdir=TB];
  node [shape=box, style="rounded", fontname="monospace"];
  edge [fontname="monospace"];
  n0 [label="thresh(2 of 3)"];
  n1 [label="key 1"];
  n0 -> n1;
  n2 [label="key 2"];
  n0 -> n2;
  n3 [label="key 3"];
  n0 -> n3;
}
`;

const LIANA_DOT = `digraph miniscript_policy {
  graph [rankdir=TB];
  node [shape=box, style="rounded", fontname="monospace"];
  edge [fontname="monospace"];
  n0 [label="thresh(1 of 2)"];
  n1 [label="key 1"];
  n0 -> n1;
  n2 [label="thresh(2 of 2)"];
  n0 -> n2;
  n3 [label="key 2"];
  n2 -> n3;
  n4 [label="older(65535)"];
  n2 -> n4;
}
`;

const LIANA_RECOVERY_DOT = `digraph liana_recovery_tree {
  graph [rankdir=TB];
  node [shape=box, style="rounded", fontname="monospace"];
  edge [fontname="monospace"];
  n0 [label="Liana recovery tree"];
  n1 [label="Primary path\\n1 key\\navailable now"];
  n0 -> n1;
  n2 [label="Recovery path 1\\n1 key\\nafter 65,535 blocks (~455 days)"];
  n0 -> n2;
}
`;

describe("PolicyTree (US-088)", () => {
  it("lays out the redacted 2-of-3 DOT policy as an SVG tree", () => {
    const layout = parsePolicyDot(MULTISIG_DOT);

    expect(layout?.nodes.map((node) => node.label)).toEqual([
      "thresh(2 of 3)",
      "key 1",
      "key 2",
      "key 3",
    ]);
    expect(layout?.edges).toHaveLength(3);
  });

  it("renders the Liana timelock policy labels without key material", () => {
    render(<PolicyTree dot={LIANA_DOT} />);

    expect(screen.getByRole("img", { name: /Miniscript policy tree/ })).toBeInTheDocument();
    expect(screen.getByText("thresh(1 of 2)")).toBeInTheDocument();
    expect(screen.getByText("older(65535)")).toBeInTheDocument();
    expect(screen.getByText("key 1")).toBeInTheDocument();
    expect(screen.queryByText(/tpub|xpub/)).toBeNull();
  });

  it("renders multi-line Liana recovery path labels", () => {
    const layout = parsePolicyDot(LIANA_RECOVERY_DOT);

    expect(layout?.nodes.map((node) => node.label)).toEqual([
      "Liana recovery tree",
      "Primary path\n1 key\navailable now",
      "Recovery path 1\n1 key\nafter 65,535 blocks (~455 days)",
    ]);

    render(<PolicyTree dot={LIANA_RECOVERY_DOT} />);
    expect(screen.getByText("Primary path")).toBeInTheDocument();
    expect(screen.getByText("after 65,535 blocks (~455 days)")).toBeInTheDocument();
  });
});
