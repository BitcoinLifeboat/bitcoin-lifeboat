#!/usr/bin/env node
import { accessSync, constants, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const childFlag = "--child";
const isChild = process.argv.includes(childFlag);
const playwrightBin = join(root, "node_modules", ".bin", "playwright");

function canRun(command, args) {
  const result = spawnSync(command, args, { stdio: "ignore" });
  return result.status === 0;
}

function run(command, args, env = {}) {
  return spawnSync(command, args, {
    cwd: root,
    env: { ...process.env, ...env },
    stdio: "inherit",
  });
}

if (!isChild) {
  if (process.platform !== "linux") {
    console.error("No-network E2E is implemented for Linux namespaces in this story.");
    process.exit(1);
  }

  const env = { LIFEBOAT_E2E_NETWORK_ISOLATED: "1" };
  const childArgs = [fileURLToPath(import.meta.url), childFlag];

  if (canRun("unshare", ["-n", "true"])) {
    console.log("Running Playwright E2E under unshare -n (network namespace).");
    const result = run("unshare", ["-n", process.execPath, ...childArgs], env);
    process.exit(result.status ?? 1);
  }

  if (canRun("bwrap", ["--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc", "--unshare-net", "/usr/bin/true"])) {
    console.log("Running Playwright E2E under bubblewrap --unshare-net (network namespace).");
    const result = run(
      "bwrap",
      [
        "--bind",
        "/",
        "/",
        "--dev",
        "/dev",
        "--proc",
        "/proc",
        "--unshare-net",
        process.execPath,
        ...childArgs,
      ],
      env,
    );
    process.exit(result.status ?? 1);
  }

  console.error("Neither unshare -n nor bubblewrap --unshare-net is available.");
  process.exit(1);
}

try {
  accessSync(playwrightBin, constants.X_OK);
} catch {
  console.error("Playwright is not installed. Run npm install in apps/desktop first.");
  process.exit(1);
}

const interfaces = readFileSync("/proc/net/dev", "utf8")
  .split("\n")
  .slice(2)
  .map((line) => line.split(":")[0]?.trim())
  .filter(Boolean)
  .sort();
const egressInterfaces = interfaces.filter((name) => name !== "lo");
if (egressInterfaces.length > 0) {
  console.error(`Network namespace still exposes egress interfaces: ${egressInterfaces.join(", ")}`);
  process.exit(1);
}

console.log("Network namespace active with only loopback exposed.");
console.log("The browser guard allows only loopback/data/blob URLs.");
const result = run(playwrightBin, ["test", "--project=chromium"], {
  LIFEBOAT_E2E_NETWORK_ISOLATED: "1",
  PLAYWRIGHT_HTML_OPEN: "never",
});
process.exit(result.status ?? 1);
