import { createRequire } from 'node:module';
import assert from 'node:assert/strict';
import path from 'node:path';
import fs from 'node:fs/promises';
import express from 'express';

const require = createRequire(import.meta.url);
const engines = require(require.resolve('playwright', { paths: [process.env.PLAYWRIGHT_MODULES || process.cwd()] }));
const app = express();
app.use(express.static(path.resolve('..', 'frontend')));
const server = app.listen(0, '127.0.0.1');
await new Promise(resolve => server.once('listening', resolve));
let browser;
try {
  for (const engine of (process.env.TEST_BROWSERS || 'chromium,firefox,webkit').split(',')) {
  browser = await engines[engine].launch({ headless: true });
  for (const [width, height] of [[320, 568], [390, 844], [768, 1024], [1366, 900], [844, 390]]) {
    const page = await browser.newPage({ viewport: { width, height } });
    let role = 'admin', signedIn = true;
    const errors = []; page.on('pageerror', e => errors.push(e.message));
    await page.route('**/*', async route => {
      const url = new URL(route.request().url());
      if (url.hostname !== '127.0.0.1') return route.abort();
      if (url.pathname === '/portal/me') return route.fulfill(signedIn ? { json: { user: { id: role, uid: role, name: 'Persona de prueba con nombre extenso', role } } } : { status: 401, json: { error: 'Inicia sesion' } });
      if (url.pathname === '/portal/summary') return route.fulfill({ json: { insideCount: 42, guardCounts: { total: 11, active: 10, inactive: 1 } } });
      if (url.pathname === '/portal/guard-report') return route.fulfill({ json: { guardCounts: { total: 11, active: 10, inactive: 1 }, data: [{ id: 'guard', name: url.searchParams.has('cursor') ? 'Segundo turno' : 'Primer turno', shiftId: 'shift', startTimestamp: 1000, approvedAccesses: 12, rejectedAccesses: 1, totalAccesses: 13, countsComplete: url.searchParams.has('cursor') }], nextCursor: url.searchParams.has('cursor') ? null : 'guard-cursor' } });
      if (url.pathname === '/portal/guard/shift') return route.fulfill({ json: { active: false } });
      if (url.pathname === '/portal/users') return route.fulfill({ json: { data: [{ id: 'member-1', uid: 'uid-1', name: '<b>Nombre literal</b>', email: 'example@example.test', role: 'member', active: true }] } });
      if (url.pathname === '/portal/student-qr/member-1') return route.fulfill({ json: { name: '<b>Nombre literal</b>', qrDataUrl: 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+a5HkAAAAASUVORK5CYII=', expiresAt: Date.now() + 1200 } });
      if (url.pathname === '/validate') return route.abort();
      if (url.pathname === '/portal/history') {
        const next = url.searchParams.has('cursor');
        return route.fulfill({ json: { data: [{ key: next ? 'b' : 'a', id: 'persona', name: url.searchParams.get('search') || (next ? 'Segunda persona' : 'Primera persona'), timestamp: Date.now(), authorized: true, sede: 'Chillan', tipoUsuario: 'estudiante', reason: 'ok' }], nextCursor: next ? null : 'test-cursor' } });
      }
      return route.continue();
    });
    await page.goto(`http://127.0.0.1:${server.address().port}/portal.html#history`);
    const visibleHistory = page.locator(width <= 650 ? '#history-mobile' : '#history-rows');
    await visibleHistory.getByText('Primera persona', { exact: false }).waitFor();
    await page.locator('#history-next').click();
    await visibleHistory.getByText('Segunda persona', { exact: false }).waitFor();
    assert.ok(await page.locator('#history-next').isDisabled());
    await page.locator('#history-prev').click();
    await visibleHistory.getByText('Primera persona', { exact: false }).waitFor();
    if (width <= 650) await page.locator('.history-filter-panel>summary').click();
    await page.locator('#history-filter').fill('Nombre filtrado');
    await visibleHistory.getByText('Nombre filtrado', { exact: false }).waitFor();
    if (width <= 650) {
      await page.locator('.history-filter-panel>summary').click();
      await page.locator('.history-item>summary').click();
      assert.ok(await page.locator('.history-item dd').first().isVisible());
      await page.locator('#menu').click();
      assert.equal(await page.locator('#menu').getAttribute('aria-expanded'), 'true');
      await page.keyboard.press('Escape');
      assert.equal(await page.locator('#menu').getAttribute('aria-expanded'), 'false');
    }
    assert.ok(await page.locator('#history-prev').isDisabled());
    assert.match(await page.locator('#history-count').innerText(), /Página 1/);
    assert.deepEqual(errors, []);
    assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1));
    await fs.mkdir('output/history-qa', { recursive: true });
    await page.screenshot({ path: `output/history-qa/${engine}-history-${width}.png`, fullPage: true });
    await page.evaluate(() => { location.hash = '#users'; });
    await page.locator('[data-qr-id]').click();
    await page.locator('#admin-qr-image').waitFor();
    assert.equal(await page.locator('#admin-qr-title').textContent(), '<b>Nombre literal</b>');
    assert.equal(await page.locator('#admin-qr-title b').count(), 0);
    await page.waitForFunction(() => document.getElementById('admin-qr-status').textContent.includes('QR vencido'));
    assert.ok(await page.locator('#admin-qr-image').isHidden());
    await page.locator('#admin-qr-close').click();
    assert.equal(await page.locator('#admin-qr-image').getAttribute('src'), null);
    await page.evaluate(() => { location.hash = '#guards'; });
    await page.locator('#guard-rows').getByText('Primer turno', { exact: false }).waitFor();
    assert.equal(await page.locator('#guard-stats .stat strong').first().textContent(), '11');
    assert.match(await page.locator('#guard-count').innerText(), /Conteo parcial/);
    await page.locator('#guard-next').click();
    await page.locator('#guard-rows').getByText('Segundo turno', { exact: false }).waitFor();
    assert.ok(await page.locator('#guard-next').isDisabled());
    await page.locator('#guard-prev').click();
    await page.locator('#guard-rows').getByText('Primer turno', { exact: false }).waitFor();
    assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1));
    role = 'guard';
    await page.goto(`http://127.0.0.1:${server.address().port}/portal.html?role=guard#scan`);
    await page.locator('#scan-view').waitFor();
    await page.evaluate(() => { window.Html5Qrcode = class { async start() { throw new DOMException('Denied', 'NotAllowedError'); } }; });
    await page.locator('#start-camera').click();
    await page.waitForFunction(() => /denegado|no permite/.test(document.getElementById('scan-result').textContent));
    await page.locator('#qr-value').fill('synthetic-test-token');
    await page.locator('#validate-button').click();
    await page.waitForFunction(() => document.getElementById('scan-result').textContent.includes('Sin confirmación'));
    assert.notEqual(await page.locator('#scan-result').getAttribute('data-ok'), 'true');
    assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1));
    await page.screenshot({ path: `output/history-qa/${engine}-guard-${width}.png`, fullPage: true });
    await page.reload();
    await page.locator('#scan-view').waitFor();
    await page.evaluate(() => {
      window.cameraStopped = 0;
      window.Html5Qrcode = class {
        async start() { await new Promise(resolve => setTimeout(resolve, 300)); }
        async stop() { window.cameraStopped++; }
      };
    });
    if (await page.evaluate(() => Boolean(navigator.mediaDevices?.getUserMedia))) {
      await page.locator('#start-camera').click();
      await page.evaluate(() => { location.hash = '#history'; });
      await page.waitForFunction(() => window.cameraStopped === 1);
      await page.evaluate(() => { location.hash = '#scan'; });
      await page.locator('#start-camera').click();
      await page.waitForFunction(() => !document.getElementById('stop-camera').disabled);
      await page.evaluate(() => {
        Object.defineProperty(document, 'hidden', { configurable: true, value: true });
        document.dispatchEvent(new Event('visibilitychange'));
      });
      await page.waitForFunction(() => window.cameraStopped === 2);
    }
    signedIn = false;
    await page.reload();
    await page.locator('#login').waitFor();
    assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1));
    assert.deepEqual(errors, []);
    await page.close();
    console.log(`PASS ${engine} ${width}x${height}: history, filters, mobile details/menu, camera denial/lifecycle, unconfirmed access, login layout`);
  }
  await browser.close(); browser = null;
  }
} finally { await browser?.close(); await new Promise(resolve => server.close(resolve)); }
