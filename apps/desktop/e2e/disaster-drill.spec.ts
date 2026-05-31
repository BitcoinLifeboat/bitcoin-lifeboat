import {
  completeOnboarding,
  expect,
  expectNoAxeViolations,
  invokedCommands,
  test,
} from "./support/tauri";

test("Disaster Drill runs DS-5 and saves the questionnaire DrillResult", async ({ page }) => {
  await completeOnboarding(page);

  await page.getByRole("link", { name: "Disaster Drill" }).click();
  await expect(page.getByRole("heading", { name: "Disaster Drill" })).toBeVisible();
  await expect(page.getByRole("radio", { name: /DS-5: I have my descriptor/ })).toBeChecked();

  await page.getByRole("button", { name: "Use sample descriptor" }).click();
  await page.getByRole("button", { name: "Run questionnaire drill" }).click();

  await expect(page.getByRole("heading", { name: "Drill passed for this scenario" })).toBeVisible();
  await expect(page.getByText("Available signers meet the threshold")).toBeVisible();
  await expect(page.getByText("Known address matches the derived range")).toBeVisible();

  await page.getByRole("button", { name: "Save this drill result" }).click();
  await expect(page.getByText(/Saved locally:/)).toBeVisible();

  await expectNoAxeViolations(page);
  await expect(invokedCommands(page)).resolves.toEqual(
    expect.arrayContaining([
      "load_settings",
      "detect_sensitive_input",
      "run_disaster_questionnaire_drill",
      "save_disaster_questionnaire_drill_result",
    ]),
  );
});

test("Disaster Drill simulates losing signer 2 of a 2-of-3 wallet", async ({ page }) => {
  await completeOnboarding(page);

  await page.getByRole("link", { name: "Disaster Drill" }).click();
  await page.getByRole("radio", { name: /MS-MISSING: Missing signer drill/ }).check();
  await page.getByRole("button", { name: "Use sample descriptor" }).click();
  await expect(page.getByRole("spinbutton", { name: "Lost signer number" })).toHaveValue("2");

  await page.getByRole("button", { name: "Run missing-signer drill" }).click();

  await expect(
    page.getByRole("heading", { name: "Recovery remains possible with the remaining signers" }),
  ).toBeVisible();
  await expect(page.getByText("Signer 1, Signer 3")).toBeVisible();
  await expect(page.getByText("Signer 1 device or seed backup")).toBeVisible();
  await expect(page.getByText("Signer 3 device or seed backup")).toBeVisible();
  await expect(page.getByText("Remaining signers meet the threshold")).toBeVisible();

  await page.getByRole("button", { name: "Save this drill result" }).click();
  await expect(page.getByText(/Saved locally:/)).toBeVisible();

  await expectNoAxeViolations(page);
  await expect(invokedCommands(page)).resolves.toEqual(
    expect.arrayContaining([
      "load_settings",
      "detect_sensitive_input",
      "run_missing_signer_drill",
      "save_missing_signer_drill_result",
    ]),
  );
});

test("Disaster Drill runs DS-9 through QR PSBT signing", async ({ page }) => {
  await completeOnboarding(page);

  await page.getByRole("link", { name: "Disaster Drill" }).click();
  await page.getByRole("radio", { name: /DS-9: I want to test a PSBT signing workflow/ }).check();
  await page.getByRole("radio", { name: /QR Show animated PSBT QR frames/ }).check();
  await page.getByRole("button", { name: "Start signing drill" }).click();

  await expect(page.getByText("bcrt1qds9destination")).toBeVisible();
  await page
    .getByLabel("I verified this destination address on the signing device.")
    .check();

  await page.getByRole("button", { name: "Generate QR frames" }).click();
  await expect(
    page.getByRole("img", { name: "Disaster drill unsigned PSBT QR frame 1 of 1" }),
  ).toBeVisible();
  await page.getByRole("button", { name: "Scan camera frame" }).click();

  await expect(page.getByRole("heading", { name: "Signing drill passed" })).toBeVisible();
  await expect(page.getByText("Required quorum signed the PSBT")).toBeVisible();
  await expect(page.getByText("Final transaction pays the confirmed destination")).toBeVisible();

  await page.getByRole("button", { name: "Save this drill result" }).click();
  await expect(page.getByText(/Saved locally:/)).toBeVisible();

  await expectNoAxeViolations(page);
  await expect(invokedCommands(page)).resolves.toEqual(
    expect.arrayContaining([
      "load_settings",
      "start_disaster_signing_drill",
      "encode_psbt_qr_frames",
      "capture_psbt_qr_payloads",
      "decode_psbt_qr_payloads",
      "complete_disaster_signing_drill",
      "save_disaster_signing_drill_result",
    ]),
  );
});

test("Disaster Drill gates mainnet PSBT files behind a session acknowledgement", async ({
  page,
}) => {
  await completeOnboarding(page);

  await page.getByRole("link", { name: "Disaster Drill" }).click();
  await page.getByRole("radio", { name: /DS-9: I want to test a PSBT signing workflow/ }).check();
  await page.getByRole("radio", { name: /Mainnet file/ }).check();

  const importButton = page.getByRole("button", { name: "Import mainnet PSBT" });
  await expect(importButton).toBeDisabled();
  await expect(page.getByText("Acknowledge the mainnet warning to import a file.")).toBeVisible();

  await page
    .getByLabel(/I want to sign a mainnet PSBT in the file-based flow/)
    .check();
  await importButton.click();

  await expect(page.getByText(/Mainnet PSBT validated from:/)).toBeVisible();
  await expect(page.getByText("No broadcast was made or offered.")).toBeVisible();
  await expect(
    page.getByText("4444444444444444444444444444444444444444444444444444444444444444"),
  ).toBeVisible();
  await expect(page.getByRole("button", { name: /Broadcast/ })).toHaveCount(0);

  await expectNoAxeViolations(page);
  const commands = await invokedCommands(page);
  expect(commands).toEqual(
    expect.arrayContaining([
      "load_settings",
      "plugin:dialog|open",
      "read_psbt_file",
      "validate_mainnet_file_psbt",
    ]),
  );
  expect(commands).not.toContain("start_disaster_signing_drill");
  expect(commands).not.toContain("broadcast_signet_transaction");
});
