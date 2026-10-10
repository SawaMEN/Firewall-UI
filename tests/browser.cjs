const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const { chromium } = require(path.join(process.env.PLAYWRIGHT_TOOLS, 'node_modules/playwright'));
(async () => {
  const browser = await chromium.launch({ headless: true, args: ['--no-sandbox', '--no-proxy-server', '--host-resolver-rules=MAP panel.test 127.0.0.1'] });
  const base = process.env.FIREWALL_UI_BROWSER_URL || 'http://panel.test:18123';
  const output = process.env.FIREWALL_UI_SCREENSHOTS || '/tmp/firewall-ui-ui-shots';
  fs.mkdirSync(output, { recursive: true });
  const context = await browser.newContext({ viewport: { width: 1440, height: 1000 } });
  await context.addCookies([{ name: 'firewall_ui_session', value: 'obsolete-secure-cookie', domain: new URL(base).hostname, path: '/', secure: true, httpOnly: true, sameSite: 'Strict' }]);
  const page = await context.newPage();
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  async function signIn(target) {
    await target.getByLabel('Имя пользователя', { exact: true }).fill('admin');
    await target.getByLabel('Пароль', { exact: true }).fill('1');
    await target.getByRole('button', { name: 'Войти', exact: true }).click();
  }
  await page.goto(base);
  await page.getByRole('button', { name: 'Войти', exact: true }).waitFor();
  assert.equal(await page.evaluate(() => document.documentElement.dataset.theme), 'cyberpunk');
  await page.screenshot({ path: path.join(output, 'login.png') });
  await signIn(page);
  await page.locator('.page-header').waitFor();
  await page.locator('.dashboard-stat').first().waitFor();
  assert.equal(await page.evaluate(async () => (await fetch('/api/session')).status), 200);
  await page.screenshot({ path: path.join(output, 'overview-desktop.png'), fullPage: true });
  await page.getByRole('menuitem', { name: 'Настройки' }).click();
  await page.getByRole('button', { name: 'Сохранить настройки' }).waitFor();
  assert.equal(await page.locator('input[type=file]').evaluate(input => getComputedStyle(input).display), 'none');
  await page.screenshot({ path: path.join(output, 'settings-desktop.png'), fullPage: true });
  await page.setViewportSize({ width: 390, height: 844 });
  assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth), 'Mobile layout overflows');
  await page.screenshot({ path: path.join(output, 'settings-mobile.png'), fullPage: true });
  assert.deepEqual(errors, []);
  // The login response alone must never mount protected pages without a cookie.
  const blocked = await browser.newContext();
  const blockedPage = await blocked.newPage();
  await blockedPage.route('**/api/login', route => route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ success: true, obj: { csrf: 'fixture' }, msg: '' }) }));
  await blockedPage.goto(base);
  await signIn(blockedPage);
  await blockedPage.getByText(/Браузер не сохранил сессию/).waitFor();
  assert.equal(await blockedPage.locator('.page-header').count(), 0);
  await browser.close();
  console.log('Browser login/session, cookie rejection and cyberpunk desktop/mobile checks passed');
})().catch(error => { console.error(error); process.exit(1); });
