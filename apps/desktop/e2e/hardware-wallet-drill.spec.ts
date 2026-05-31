import {
  completeOnboarding,
  expect,
  expectNoAxeViolations,
  invokedCommands,
  test,
} from "./support/tauri";

test("Hardware Wallet Drill runs the HWI sidecar signing path", async ({ page }) => {
  await completeOnboarding(page);

  await page.getByRole("link", { name: "Test a Hardware Wallet" }).click();
  await expect(page.getByRole("heading", { name: "Hardware Wallet Drill" })).toBeVisible();
  await expect(page.getByText("Device detected is not wallet recoverable.")).toBeVisible();

  await page.getByRole("radio", { name: /HWI sidecar/ }).check();
  await page.getByRole("button", { name: "Start hardware drill" }).click();
  await expect(page.getByText("bcrt1qhardwaredrilldestination")).toBeVisible();

  await page.getByRole("button", { name: "Check connected devices" }).click();
  await expect(page.getByText("trezor_safe_5 (a1b2c3d4)")).toBeVisible();

  await page
    .getByLabel("I verified this destination address on the signing device.")
    .check();
  await page.getByRole("button", { name: "Sign with HWI sidecar" }).click();

  await expect(page.getByRole("heading", { name: "Hardware drill passed" })).toBeVisible();
  await expect(page.getByText("Required quorum signed the PSBT")).toBeVisible();

  await page.getByRole("button", { name: "Save this drill result" }).click();
  await expect(page.getByText(/Saved locally:/)).toBeVisible();

  await expectNoAxeViolations(page);
  await expect(invokedCommands(page)).resolves.toEqual(
    expect.arrayContaining([
      "load_settings",
      "start_disaster_signing_drill",
      "enumerate_hwi_devices",
      "sign_hwi_psbt",
      "complete_disaster_signing_drill",
      "save_disaster_signing_drill_result",
    ]),
  );
});
