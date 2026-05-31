import {
  blockedPracticeMnemonic,
  completeOnboarding,
  expect,
  expectNoAxeViolations,
  invokedCommands,
  test,
} from "./support/tauri";
import type { Page } from "@playwright/test";

const defaultPracticeMnemonic =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

async function pasteIntoSeedField(page: Page, text: string): Promise<void> {
  await page.getByRole("textbox", { name: "Practice seed words" }).evaluate((node, value) => {
    const data = new DataTransfer();
    data.setData("text/plain", value);
    node.dispatchEvent(
      new ClipboardEvent("paste", {
        bubbles: true,
        cancelable: true,
        clipboardData: data,
      }),
    );
  }, text);
}

test("Practice Mode pre-fills the documented test seed and hard-blocks a real-looking seed", async ({
  page,
}) => {
  await completeOnboarding(page);

  await page.getByRole("link", { name: "Practice Recovery Safely" }).click();
  await expect(page.getByRole("heading", { name: "Practice Mode" })).toBeVisible();
  await expect(page.getByText("PRACTICE-ONLY")).toBeVisible();
  await expect(page.getByRole("textbox", { name: "Practice seed words" })).toHaveValue(
    defaultPracticeMnemonic,
  );

  await pasteIntoSeedField(page, blockedPracticeMnemonic);

  await expect(
    page.getByRole("alertdialog", { name: "Practice Mode blocked that seed phrase" }),
  ).toBeVisible();
  await expect(
    page.getByText(
      "This looks like a real mnemonic, not a practice one. Practice Mode only accepts the documented test seeds. See practice-seeds.md.",
    ),
  ).toBeVisible();
  await expect(page.getByRole("textbox", { name: "Practice seed words" })).toHaveValue(
    defaultPracticeMnemonic,
  );

  await expectNoAxeViolations(page);
  await expect(invokedCommands(page)).resolves.toEqual(
    expect.arrayContaining(["load_settings", "detect_sensitive_input"]),
  );
});

test("Practice Mode runs the receive/send drill and opens the Signet faucet via command", async ({
  page,
}) => {
  await completeOnboarding(page);

  await page.getByRole("link", { name: "Practice Recovery Safely" }).click();
  await page.getByRole("button", { name: "Start receive step" }).click();

  await expect(page.getByText("bcrt1qpracticeaddress")).toBeVisible();
  await page.getByRole("button", { name: "Create, sign, finalize" }).click();
  await expect(page.getByRole("heading", { name: "Drill result" })).toBeVisible();
  await expect(
    page.getByText("No broadcast was made. Signet broadcast is unavailable for regtest."),
  ).toBeVisible();
  await page.getByRole("button", { name: "Save unsigned PSBT" }).click();
  await expect(page.getByText(/Unsigned PSBT saved:/)).toBeVisible();
  await page.getByRole("button", { name: "Import signed PSBT" }).click();
  await expect(page.getByText("Signed PSBT validated and finalized.")).toBeVisible();
  await expect(page.getByText(/Imported from:/)).toBeVisible();
  await page.getByRole("button", { name: "Generate QR frames" }).click();
  await expect(page.getByRole("img", { name: "Unsigned PSBT QR frame 1 of 1" })).toBeVisible();
  await expect(page.getByText("Frame 1 of 1")).toBeVisible();
  await page.getByRole("button", { name: "Scan camera frame" }).click();
  await expect(page.getByText("Signed QR PSBT validated and finalized.")).toBeVisible();
  await expect(page.getByRole("button", { name: "Save this drill result" })).toBeVisible();
  await page.getByRole("button", { name: "Save this drill result" }).click();
  await expect(page.getByText(/Saved locally:/)).toBeVisible();

  await page.getByRole("radio", { name: /Signet/ }).check();
  await page.getByRole("button", { name: "Start receive step" }).click();
  await expect(page.getByText("tb1qpracticeaddress")).toBeVisible();
  await expect(page.getByText("Lifeboat does not call the faucet.")).toBeVisible();

  await page.getByRole("button", { name: "Open Signet faucet" }).click();
  await expect(page.getByText("Faucet opened in your browser.")).toBeVisible();

  await page.getByRole("button", { name: "Create, sign, finalize" }).click();
  await expect(
    page.getByText("Network call to https://mutinynet.com/api/tx only after confirmation."),
  ).toBeVisible();
  await page.getByRole("button", { name: "Broadcast on Signet" }).click();
  const dialog = page.getByRole("alertdialog", { name: "Confirm Signet broadcast" });
  await expect(dialog).toBeVisible();
  await expect(dialog.getByText("Network call to")).toBeVisible();
  await expect(dialog.getByText("https://mutinynet.com/api/tx")).toBeVisible();
  await expect(
    dialog.getByText("Network: SIGNET. Mainnet broadcast is not available in Bitcoin Lifeboat."),
  ).toBeVisible();
  await dialog.getByRole("button", { name: "Broadcast on Signet" }).click();
  await expect(page.getByText(/Signet broadcast accepted:/)).toBeVisible();

  await expectNoAxeViolations(page);
  await expect(invokedCommands(page)).resolves.toEqual(
    expect.arrayContaining([
      "load_settings",
      "start_practice_drill",
      "run_practice_send_drill",
      "plugin:dialog|save",
      "save_export",
      "plugin:dialog|open",
      "read_psbt_file",
      "finalize_file_psbt",
      "encode_psbt_qr_frames",
      "capture_psbt_qr_payloads",
      "decode_psbt_qr_payloads",
      "save_practice_drill_result",
      "broadcast_signet_transaction",
      "open_external_link",
    ]),
  );
});
