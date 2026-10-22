const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const { chromium } = require(path.join(process.env.PLAYWRIGHT_TOOLS, 'node_modules/playwright'));
(async () => {
  const browser = await chromium.launch({ headless: true, args: ['--no-sandbox', '--no-proxy-server', '--host-resolver-rules=MAP panel.test 127.0.0.1'] });
  const base = process.env.FIREWALL_UI_BROWSER_URL || 'http://panel.test:18123';
  const output = process.env.FIREWALL_UI_SCREENSHOTS || '/tmp/firewall-ui-ui-shots';
  fs.mkdirSync(output, { recursive: true });
  // Hold session bootstrap so geometry is measured before the loader disappears.
  const loadingContext = await browser.newContext();
  const loadingPage = await loadingContext.newPage();
  let releaseSession;
  const sessionGate = new Promise(resolve => { releaseSession = resolve; });
  await loadingPage.route('**/api/session', async route => {
    await sessionGate;
    await route.fulfill({ status: 401, contentType: 'application/json', body: JSON.stringify({ success: false, msg: 'authentication required' }) });
  });
  await loadingPage.goto(base);
  await loadingPage.locator('.app-loading .ant-spin').waitFor();
  for (const viewport of [{ width: 1440, height: 1000 }, { width: 390, height: 844 }]) {
    await loadingPage.setViewportSize(viewport);
    const geometry = await loadingPage.evaluate(() => {
      const overlay = document.querySelector('.app-loading').getBoundingClientRect();
      const spinner = document.querySelector('.app-loading .ant-spin-dot').getBoundingClientRect();
      return { x: spinner.x + spinner.width / 2 - innerWidth / 2,
        y: spinner.y + spinner.height / 2 - innerHeight / 2,
        width: overlay.width, height: overlay.height, overflow: document.documentElement.scrollWidth > innerWidth };
    });
    assert.ok(Math.abs(geometry.x) < 1 && Math.abs(geometry.y) < 1, `Loader is off center: ${JSON.stringify(geometry)}`);
    assert.equal(geometry.width, viewport.width);
    assert.equal(geometry.height, viewport.height);
    assert.equal(geometry.overflow, false);
  }
  releaseSession();
  await loadingPage.getByRole('button', { name: 'Войти', exact: true }).waitFor();
  await loadingContext.close();
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
  const updateStatus = { currentVersion: '1.3.2', currentChannel: 'stable', selectedChannel: 'stable', latestVersion: '1.3.99', latestCommit: 'fixture-next', available: true };
  const json = (route, obj) => route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ success: true, obj, msg: '' }) });
  await page.route('**/api/update/status*', route => json(route, updateStatus));
  await page.goto(base);
  await page.getByRole('button', { name: 'Войти', exact: true }).waitFor();
  assert.equal(await page.evaluate(() => document.documentElement.dataset.theme), 'cyberpunk');
  assert.equal(await page.locator('link[rel=icon]').getAttribute('href'), '/favicon.svg');
  assert.equal(await page.evaluate(async () => {
    const response = await fetch('/favicon.svg');
    return response.ok && response.headers.get('content-type').includes('image/svg+xml') && (await response.text()).includes('<svg');
  }), true);
  await page.screenshot({ path: path.join(output, 'login.png') });
  await signIn(page);
  await page.locator('.page-header').waitFor();
  // Firewall is now the home page; navigate explicitly before overview checks.
  await page.getByRole('menuitem', { name: 'Обзор' }).click();
  await page.locator('.dashboard-stat').first().waitFor();
  assert.equal(await page.evaluate(async () => (await fetch('/api/session')).status), 200);
  assert.deepEqual(await page.locator('.sider-nav').evaluate(node => ({ color: getComputedStyle(node).backgroundColor, image: getComputedStyle(node).backgroundImage })), { color: 'rgba(0, 0, 0, 0)', image: 'none' });
  const trigger = page.locator('.ant-layout-sider-trigger');
  assert.equal(await trigger.evaluate(node => getComputedStyle(node).backgroundColor), 'rgba(0, 0, 0, 0)');
  await page.screenshot({ path: path.join(output, 'overview-desktop.png'), fullPage: true });
  await trigger.click();
  await page.locator('.ant-layout-sider-collapsed').waitFor();
  await page.screenshot({ path: path.join(output, 'sidebar-collapsed.png') });
  await trigger.click();
  await page.locator('.update-banner').getByText('Доступно обновление Firewall-UI 1.3.99').waitFor();
  let finishUpdate;
  let markUpdateStarted;
  const updateStarted = new Promise(resolve => { markUpdateStarted = resolve; });
  await page.route('**/api/update/apply', async route => {
    await new Promise(resolve => { finishUpdate = resolve; markUpdateStarted(); });
    await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ success: false, msg: 'fixture: checksum mismatch' }) });
  });
  await page.locator('.update-banner').getByRole('button', { name: 'Обновить', exact: true }).click();
  await page.getByRole('dialog').getByRole('button', { name: 'Установить', exact: true }).click();
  await page.getByRole('dialog').getByText('Не закрывайте и не обновляйте страницу.').waitFor();
  await page.waitForFunction(() => document.querySelector('.ant-modal .ant-spin-spinning') !== null);
  // The POST remains pending while the progress window is already visible.
  await updateStarted;
  assert.ok(finishUpdate, 'Update POST did not start');
  finishUpdate();
  await page.getByRole('dialog').getByText('fixture: checksum mismatch').waitFor();
  await page.getByRole('dialog').locator('.ant-modal-close').click();
  await page.getByRole('menuitem', { name: 'Настройки' }).click();
  await page.getByRole('button', { name: 'Сохранить настройки' }).waitFor();
  assert.equal(await page.locator('input[type=file]').evaluate(input => getComputedStyle(input).display), 'none');
  // Restoring a backup must hydrate the form before a later save can use it.
  let settingsFixture = await page.evaluate(async () => (await (await fetch('/api/settings')).json()).obj);
  await page.route('**/api/settings', route => json(route, settingsFixture));
  await page.route('**/api/backup/restore', route => {
    settingsFixture = { ...settingsFixture, publicHost: 'restored.example.com', externalPort: 443, secureCookies: true };
    return json(route, { restored: true, restartRequired: false });
  });
  await page.locator('input[type=file]').setInputFiles({ name: 'backup.json', mimeType: 'application/json', buffer: Buffer.from('{"version":1}') });
  await page.waitForFunction(() => document.querySelector('#publicHost')?.value === 'restored.example.com');
  await page.getByText('https://restored.example.com:443/', { exact: true }).waitFor();

  await page.screenshot({ path: path.join(output, 'settings-desktop.png'), fullPage: true });
  await page.setViewportSize({ width: 390, height: 844 });
  assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth), 'Mobile layout overflows');
  await page.screenshot({ path: path.join(output, 'settings-mobile.png'), fullPage: true });
  // Exercise compact rules and deletion against isolated API fixtures.
  await page.setViewportSize({ width: 1440, height: 1000 });
  let manual = ['tcp', 'udp'].map(protocol => ({ port: 9000, protocol, label: 'paired manual' }));
  let advanced = ['tcp', 'udp'].map(protocol => ({ id: `paired-${protocol}`, protocol, action: 'allow', portStart: 9001, portEnd: 9002, sourceCidr: '', interface: '', ipVersion: 'any', priority: 100, label: 'paired advanced' }));
  const requests = [];
  const status = () => ({ supported: true, backend: 'ufw', enabled: true, autoSync: false, pingEnabled: true,
    rules: manual.map(rule => ({ ...rule, source: 'manual', owned: true, exists: true })), manualRules: manual });
  const response = (route, obj) => route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ success: true, obj, msg: '' }) });
  await page.route('**/api/firewall/status', route => response(route, status()));
  await page.route('**/api/firewall/advanced', route => response(route, advanced));
  await page.route('**/api/firewall/rules/delete', route => {
    const data = route.request().postDataJSON(); requests.push(data);
    manual = manual.filter(rule => rule.port !== data.port || rule.protocol !== data.protocol);
    return response(route, status());
  });
  await page.route('**/api/firewall/advanced/delete', route => {
    const data = route.request().postDataJSON(); requests.push(data);
    advanced = advanced.filter(rule => rule.id !== data.id);
    return response(route, { rules: advanced });
  });
  await page.getByRole('menuitem', { name: 'Файрволл' }).click();
  const activeCard = page.locator('.ant-card').filter({ has: page.getByText('Активные и ожидаемые правила', { exact: true }) });
  // A matching UFW ALLOW must be shown in Russian, not the hard-coded OPEN.
  await activeCard.getByText('ОТКРЫТ', { exact: true }).first().waitFor();
  assert.equal(await activeCard.getByText('OPEN', { exact: true }).count(), 0);
  const manualCard = page.locator('.ant-card').filter({ has: page.getByText('Ручные правила', { exact: true }) });
  const manualTable = manualCard.locator(':scope > .ant-card-body > .ant-table-wrapper');
  const advancedSection = manualCard.locator('.ant-collapse-item').filter({ has: page.getByText('Расширенные правила', { exact: true }) });
  await manualTable.getByText('TCP / UDP', { exact: true }).waitFor();
  await advancedSection.locator('.ant-collapse-header').click();
  await advancedSection.getByText('TCP / UDP', { exact: true }).waitFor();
  assert.equal(await manualTable.getByRole('button', { name: 'Удалить', exact: true }).count(), 0);
  await manualTable.locator('.ant-table-row-expand-icon-collapsed').click();
  await advancedSection.locator('.ant-table-row-expand-icon-collapsed').click();
  await page.screenshot({ path: path.join(output, 'paired-rules-desktop.png'), fullPage: true });
  const manualTCP = manualTable.locator('.ant-table-expanded-row .ant-table-row').filter({ has: page.getByText('TCP', { exact: true }) });
  await manualTCP.getByRole('button', { name: 'Удалить', exact: true }).click();
  await page.locator('.ant-popconfirm').getByRole('button', { name: /OK|Да|ОК/ }).click();
  await manualTable.getByText('UDP', { exact: true }).waitFor();
  assert.deepEqual(requests[0], { port: 9000, protocol: 'tcp' });
  assert.equal(await manualTable.getByText('TCP / UDP', { exact: true }).count(), 0);
  const advancedTCP = advancedSection.locator('.ant-table-expanded-row .ant-table-row').filter({ has: page.getByText('TCP', { exact: true }) });
  await advancedTCP.getByRole('button', { name: 'Удалить', exact: true }).click();
  await page.locator('.ant-popconfirm').getByRole('button', { name: /OK|Да|ОК/ }).click();
  await advancedSection.getByText('UDP', { exact: true }).waitFor();
  assert.deepEqual(requests[1], { id: 'paired-tcp' });
  assert.deepEqual(advanced.map(rule => rule.id), ['paired-udp']);
  await page.setViewportSize({ width: 390, height: 844 });
  assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth), 'Rules mobile layout overflows');
  await page.screenshot({ path: path.join(output, 'paired-rules-mobile.png'), fullPage: true });
  assert.deepEqual(errors, []);
  // Verify that a successful POST cannot reload the old server version.
  const updating = await browser.newContext({ storageState: await context.storageState() });
  const updatePage = await updating.newPage();
  let newBuildReady = false;
  let healthChecks = 0;
  let navigations = 0;
  updatePage.on('framenavigated', frame => { if (frame === updatePage.mainFrame()) navigations++; });
  await updatePage.route('**/api/update/status*', route => json(route, updateStatus));
  await updatePage.route('**/api/update/apply', route => json(route, { ...updateStatus, available: false, restarting: true }));
  await updatePage.route('**/api/health', route => {
    healthChecks++;
    return json(route, { version: newBuildReady ? '1.3.99' : '1.3.2', commit: newBuildReady ? 'fixture-next' : 'fixture-old' });
  });
  await updatePage.goto(base);
  await updatePage.locator('.update-banner').getByRole('button', { name: 'Обновить', exact: true }).click();
  await updatePage.getByRole('dialog').getByRole('button', { name: 'Установить', exact: true }).click();
  await updatePage.getByRole('dialog').getByText('Перезапуск и проверка новой версии…').waitFor();
  await updatePage.waitForResponse('**/api/health');
  assert.equal(navigations, 1, 'Reloaded before the new build answered');
  newBuildReady = true;
  await updatePage.waitForEvent('framenavigated', { predicate: frame => frame === updatePage.mainFrame() });
  assert.ok(healthChecks >= 2, 'Did not verify the running build');
  await updating.close();
  // Docker availability uses the same banner, with instructions instead of self-update.
  const docker = await browser.newContext({ storageState: await context.storageState() });
  const dockerPage = await docker.newPage();
  await dockerPage.route('**/api/update/status*', route => json(route, { ...updateStatus, manualInstall: true }));
  await dockerPage.goto(base);
  await dockerPage.locator('.update-banner').getByRole('button', { name: 'Как обновить' }).click();
  await dockerPage.getByRole('dialog').getByText(/curl -fsSL/).waitFor();
  await docker.close();
  // The login response alone must never mount protected pages without a cookie.
  const blocked = await browser.newContext();
  const blockedPage = await blocked.newPage();
  await blockedPage.route('**/api/login', route => route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ success: true, obj: { csrf: 'fixture' }, msg: '' }) }));
  await blockedPage.goto(base);
  await signIn(blockedPage);
  await blockedPage.getByText(/Браузер не сохранил сессию/).waitFor();
  assert.equal(await blockedPage.locator('.page-header').count(), 0);
  await browser.close();
  console.log('Browser login/session, update banner/progress/restart verification, Docker instructions, backup form hydration, protocol deletion and desktop/mobile checks passed');
})().catch(error => { console.error(error); process.exit(1); });
