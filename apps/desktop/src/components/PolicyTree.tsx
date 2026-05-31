import { useId } from "react";
import { useTranslation } from "react-i18next";

interface DotEdge {
  from: number;
  to: number;
}

interface TreeNode {
  id: number;
  label: string;
  lines: string[];
  x: number;
  y: number;
}

interface TreeEdge {
  from: TreeNode;
  to: TreeNode;
}

interface PolicyTreeLayout {
  nodes: TreeNode[];
  edges: TreeEdge[];
  width: number;
  height: number;
}

interface PolicyTreeProps {
  dot: string;
}

const nodeWidth = 220;
const nodeHeight = 76;
const horizontalGap = 44;
const verticalGap = 74;
const padding = 24;
const slotWidth = nodeWidth + horizontalGap;
const lineHeight = 16;

function unescapeDotLabel(label: string): string {
  let output = "";
  for (let index = 0; index < label.length; index += 1) {
    const ch = label[index];
    if (ch !== "\\" || index + 1 >= label.length) {
      output += ch;
      continue;
    }
    index += 1;
    const escaped = label[index];
    if (escaped === "n") output += "\n";
    else if (escaped === "r") output += "\r";
    else if (escaped === "t") output += "\t";
    else output += escaped;
  }
  return output;
}

export function parsePolicyDot(dot: string): PolicyTreeLayout | null {
  const labels = new Map<number, string>();
  const children = new Map<number, number[]>();
  const rawEdges: DotEdge[] = [];
  const nodePattern = /^n(\d+) \[label="((?:\\.|[^"\\])*)"\];$/;
  const edgePattern = /^n(\d+) -> n(\d+);$/;

  for (const rawLine of dot.split("\n")) {
    const line = rawLine.trim();
    const nodeMatch = line.match(nodePattern);
    if (nodeMatch) {
      const id = Number(nodeMatch[1]);
      labels.set(id, unescapeDotLabel(nodeMatch[2]));
      continue;
    }
    const edgeMatch = line.match(edgePattern);
    if (edgeMatch) {
      const from = Number(edgeMatch[1]);
      const to = Number(edgeMatch[2]);
      rawEdges.push({ from, to });
      children.set(from, [...(children.get(from) ?? []), to]);
    }
  }

  if (!labels.has(0)) {
    return null;
  }

  let leafSlots = 0;
  const positions = new Map<number, { depth: number; slot: number }>();
  const visiting = new Set<number>();

  function layoutNode(id: number, depth: number): number {
    if (visiting.has(id)) {
      return leafSlots;
    }
    visiting.add(id);
    const childIds = children.get(id) ?? [];
    const childSlots = childIds
      .filter((childId) => labels.has(childId))
      .map((childId) => layoutNode(childId, depth + 1));

    let slot: number;
    if (childSlots.length === 0) {
      slot = leafSlots;
      leafSlots += 1;
    } else {
      slot = (childSlots[0] + childSlots[childSlots.length - 1]) / 2;
    }
    positions.set(id, { depth, slot });
    visiting.delete(id);
    return slot;
  }

  layoutNode(0, 0);

  const treeNodes: TreeNode[] = [];
  for (const [id, position] of positions.entries()) {
    const label = labels.get(id);
    if (label !== undefined) {
      const lines = label.split("\n");
      treeNodes.push({
        id,
        label,
        lines,
        x: padding + position.slot * slotWidth,
        y: padding + position.depth * (nodeHeight + verticalGap),
      });
    }
  }
  treeNodes.sort((a, b) => a.y - b.y || a.x - b.x || a.id - b.id);

  const byId = new Map(treeNodes.map((node) => [node.id, node]));
  const treeEdges: TreeEdge[] = [];
  for (const edge of rawEdges) {
    const from = byId.get(edge.from);
    const to = byId.get(edge.to);
    if (from !== undefined && to !== undefined) {
      treeEdges.push({ from, to });
    }
  }

  let maxDepth = 0;
  for (const position of positions.values()) {
    maxDepth = Math.max(maxDepth, position.depth);
  }
  const width = padding * 2 + Math.max(leafSlots, 1) * nodeWidth + Math.max(leafSlots - 1, 0) * horizontalGap;
  const height = padding * 2 + (maxDepth + 1) * nodeHeight + maxDepth * verticalGap;

  return { nodes: treeNodes, edges: treeEdges, width, height };
}

export function PolicyTree({ dot }: PolicyTreeProps): JSX.Element {
  const { t } = useTranslation();
  const titleId = useId();
  const descId = useId();
  const layout = parsePolicyDot(dot);

  if (layout === null) {
    return (
      <pre className="max-h-64 overflow-auto rounded border border-slate-200 bg-slate-50 p-3 text-xs text-slate-700 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-200">
        {dot}
      </pre>
    );
  }

  return (
    <svg
      role="img"
      aria-labelledby={`${titleId} ${descId}`}
      viewBox={`0 0 ${layout.width} ${layout.height}`}
      className="h-auto w-full overflow-visible rounded border border-slate-200 bg-white dark:border-slate-700 dark:bg-slate-950"
    >
      <title id={titleId}>{t("policyTree.ariaTitle")}</title>
      <desc id={descId}>{t("policyTree.ariaDescription")}</desc>
      <g>
        {layout.edges.map((edge) => (
          <line
            key={`${edge.from.id}-${edge.to.id}`}
            x1={edge.from.x + nodeWidth / 2}
            y1={edge.from.y + nodeHeight}
            x2={edge.to.x + nodeWidth / 2}
            y2={edge.to.y}
            className="stroke-slate-300 dark:stroke-slate-600"
            strokeWidth={2}
          />
        ))}
        {layout.nodes.map((node) => (
          <g key={node.id} transform={`translate(${node.x} ${node.y})`}>
            <rect
              width={nodeWidth}
              height={nodeHeight}
              rx={8}
              className="fill-slate-50 stroke-slate-300 dark:fill-slate-800 dark:stroke-slate-600"
              strokeWidth={1.5}
            />
            <text
              x={nodeWidth / 2}
              y={nodeHeight / 2}
              dominantBaseline="middle"
              textAnchor="middle"
              className="fill-slate-900 font-mono text-xs dark:fill-slate-100"
            >
              {node.lines.map((line, index) => (
                <tspan
                  key={`${node.id}-${line}-${index}`}
                  x={nodeWidth / 2}
                  dy={index === 0 ? -((node.lines.length - 1) * lineHeight) / 2 : lineHeight}
                >
                  {line}
                </tspan>
              ))}
            </text>
          </g>
        ))}
      </g>
    </svg>
  );
}
