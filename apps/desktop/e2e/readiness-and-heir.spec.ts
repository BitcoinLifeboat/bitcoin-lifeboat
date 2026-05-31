import {
  completeOnboarding,
  expect,
  expectNoAxeViolations,
  invokedCommands,
  test,
} from "./support/tauri";
import type { Page } from "@playwright/test";

const nextButton = { name: "Next" };

async function advanceSampleWizardToReview(page: Page): Promise<void> {
  await page.getByRole("button", nextButton).click();
  await page.getByRole("radio", { name: "Paste a descriptor" }).check();
  await page.getByRole("button", nextButton).click();
  await page.getByRole("button", { name: "Use sample descriptor" }).click();
  await page.getByRole("button", nextButton).click();
  await page.getByRole("button", nextButton).click();
  await page.getByRole("button", nextButton).click();
  await page.getByRole("button", nextButton).click();
}

test("full Readiness Check flow exports a public-safe JSON report", async ({ page }) => {
  await completeOnboarding(page);

  await page.getByRole("link", { name: "Run a Readiness Check" }).click();
  await expect(page.getByRole("heading", { name: "Run a Readiness Check" })).toBeVisible();

  await page.getByRole("button", nextButton).click();
  await page.getByRole("radio", { name: "Paste a descriptor" }).check();
  await page.getByRole("button", nextButton).click();
  await page.getByRole("button", { name: "Use sample descriptor" }).click();
  await page.getByRole("button", nextButton).click();
  await page.getByRole("button", nextButton).click();
  await page.getByRole("button", nextButton).click();
  await page.getByRole("button", nextButton).click();

  await expect(page.getByText("Needs Attention").first()).toBeVisible();
  await expect(page.getByText("Change descriptor missing").first()).toBeVisible();
  await page.getByRole("button", nextButton).click();

  await page.getByRole("radio", { name: "JSON" }).check();
  await page.getByRole("button", { name: "Export" }).click();
  await expect(page.getByText("Report saved.")).toBeVisible();

  await expectNoAxeViolations(page);
  await expect(invokedCommands(page)).resolves.toEqual(
    expect.arrayContaining([
      "load_settings",
      "audit_descriptor",
      "generate_report",
      "plugin:dialog|save",
      "save_export",
    ]),
  );
});

test("Miniscript policy trees render for 2-of-3 and Liana descriptors", async ({ page }) => {
  await completeOnboarding(page);

  await page.getByRole("link", { name: "Audit Multisig Setup" }).click();
  await expect(page.getByRole("heading", { name: "Audit Multisig Setup" })).toBeVisible();
  await advanceSampleWizardToReview(page);

  await expect(page.getByRole("heading", { name: "Policy tree" })).toBeVisible();
  await expect(page.getByText("thresh(2 of 3)")).toBeVisible();
  await expect(page.getByText("key 3")).toBeVisible();

  await page.getByRole("link", { name: "Home" }).click();
  await page.getByRole("link", { name: "Run a Readiness Check" }).click();
  await page.getByRole("radio", { name: "Liana (timelock recovery)" }).check();
  await advanceSampleWizardToReview(page);

  await expect(page.getByRole("heading", { name: "Recovery path tree" })).toBeVisible();
  await expect(page.getByText("Primary path").first()).toBeVisible();
  await expect(page.getByText("Recovery path 1").first()).toBeVisible();
  await expect(page.getByText("after 65,535 blocks (~455 days)")).toBeVisible();
  await expect(
    page.getByText("Recovery path activates after 65,535 blocks, about 455 days."),
  ).toBeVisible();
  await page.getByLabel("Current block height").fill("840000");
  await expect(
    page.getByText(
      "Based on current block 840,000, recovery path is active in 65,535 blocks.",
    ),
  ).toBeVisible();
  await expect(invokedCommands(page)).resolves.toEqual(
    expect.arrayContaining(["render_miniscript_policy_dot", "render_liana_recovery_tree"]),
  );
});

test("heir runbook flow previews blanks and exports a public-safe PDF", async ({ page }) => {
  await completeOnboarding(page);

  await page.getByRole("link", { name: "Create Heir Runbook" }).click();
  await expect(page.getByRole("heading", { name: "Create Heir Runbook" })).toBeVisible();

  await page.getByRole("radio", { name: "2-of-3 multisig (any two of three keys)" }).check();
  await page.getByRole("button", nextButton).click();
  await page.getByRole("button", { name: "Use sample descriptor" }).click();
  await page.getByRole("button", nextButton).click();

  await expect(page.getByText(/Signer A is kept at:/)).toBeVisible();
  await page.getByRole("button", { name: "Export runbook" }).click();
  await expect(page.getByText("Runbook saved.")).toBeVisible();

  await expectNoAxeViolations(page);
  await expect(invokedCommands(page)).resolves.toEqual(
    expect.arrayContaining([
      "load_settings",
      "generate_runbook",
      "plugin:dialog|save",
      "save_export",
    ]),
  );
});

test("heir walkthrough runs end to end with stop checks and confidence checks", async ({ page }) => {
  await completeOnboarding(page);

  await page
    .getByRole("navigation", { name: "Primary" })
    .getByRole("link", { name: "Run Heir Drill" })
    .click();
  await expect(page.getByRole("heading", { name: "Run Heir Drill" })).toBeVisible();
  await expect(page.getByText("Practice packet", { exact: true })).toBeVisible();
  await expect(page.getByText(/we will never contact you/).first()).toBeVisible();

  for (const heading of [
    "Start with care",
    "Find the packet",
    "Open the practice wallet",
    "Send fake coins",
    "Write the result",
  ]) {
    await expect(page.getByRole("heading", { name: heading })).toBeVisible();
    await page.getByRole("checkbox", { name: /I did this step/ }).check();
    if (heading !== "Write the result") {
      await page.getByRole("button", { name: "Next" }).click();
    }
  }

  await page.getByRole("checkbox", { name: "I found the packet folder and the practice wallet file." }).check();
  await page.getByRole("checkbox", { name: "I can explain why this drill uses fake bitcoin only." }).check();
  await page
    .getByRole("checkbox", { name: "I know real seed words never go into this app or any web site." })
    .check();
  await page
    .getByRole("checkbox", { name: "I know to stop if anyone calls, texts, or emails about this drill." })
    .check();

  await expect(
    page.getByText("You finished the walkthrough. Save or print the family receipt when that step is ready."),
  ).toBeVisible();
  await page.getByRole("button", { name: "Save receipt PDF" }).click();
  await expect(page.getByText(/Receipt saved\. Hash: sha256:/)).toBeVisible();
  await expect(page.getByText(/Stop now if/)).toBeVisible();
  await expectNoAxeViolations(page);
  await expect(invokedCommands(page)).resolves.toEqual(
    expect.arrayContaining([
      "generate_family_drill_receipt",
      "plugin:dialog|save",
      "save_export",
    ]),
  );
});
