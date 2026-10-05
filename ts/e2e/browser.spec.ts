// Runs the built library in a real browser (WebCrypto, DecompressionStream) against the Genoa fixture.
import { test, expect } from '@playwright/test';

test('verifies the real Genoa report in the browser and rejects a flipped signature', async ({ page }) => {
  await page.goto('/ts/e2e/index.html');
  const result = await page.waitForFunction(() => (window as unknown as { __result?: unknown }).__result, null, { timeout: 30_000 });
  const r = (await result.jsonValue()) as { error?: string; ok?: { ok: boolean; attestationResult?: { platform: { product: string }; identity: { measurement: string } } }; rejected?: { ok: boolean; stage: string; violations: { code: string }[] } };
  expect(r.error, r.error).toBeUndefined();
  expect(r.ok!.ok).toBe(true);
  expect(r.ok!.attestationResult!.platform.product).toBe('Genoa');
  expect(r.ok!.attestationResult!.identity.measurement).toBe('09ef32acf90fcfeb6206d1a46c13145cef736ebbb83f18eaff680b686232031546ff5fd39c44599699ee8734cbbeb519');
  expect(r.rejected!.ok).toBe(false);
  expect(r.rejected!.stage).toBe('signature');
  expect(r.rejected!.violations[0].code).toBe('REPORT_SIGNATURE_INVALID');
});
