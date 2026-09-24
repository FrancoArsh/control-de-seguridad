/* Portal navigation is driven by the server-authorized profile. */
const $ = id => document.getElementById(id);
let user, scanner, scanning = false, busy = false, viewVersion = 0, qrTimer;
let presence = [], history = [];
const links = { inicio: ['Inicio', '⌂'], scan: ['Escanear QR', '▣'], presence: ['Personas dentro', '◉'], history: ['Historial', '≡'], qr: ['Mi código QR', '▦'], users: ['Usuarios', '♙'] };
const views = { inicio: 'home', scan: 'scan', presence: 'presence', history: 'history', qr: 'qr', users: 'users' };
const allowed = () => user?.role === 'member' ? ['inicio', 'qr', 'history'] : ['inicio', 'scan', 'presence', 'history', ...(user?.role === 'admin' ? ['users'] : [])];
const date = value => value ? new Date(value).toLocaleString('es-CL') : 'Sin registros';
const escape = value => String(value ?? '').replace(/[&<>"']/g, v => ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;' })[v]);

async function api(path, body, method) {
  const response = await fetch(path, { method: method || (body === undefined ? 'GET' : 'POST'), credentials: 'same-origin', headers: { 'Content-Type': 'application/json', 'X-Portal-Request': '1' }, body: body === undefined ? undefined : JSON.stringify(body), cache: 'no-store' });
  const data = await response.json();
  if (!response.ok) {
    if (response.status === 401 && path !== '/portal/login') await showLogin();
    throw new Error(data.error || 'No fue posible completar la solicitud.');
  }
  return data;
}
async function stopCamera() {
  if (scanner && scanning) { await scanner.stop().catch(() => {}); scanning = false; }
  $('stop-camera').disabled = true;
  $('start-camera').disabled = false;
}
async function showLogin() {
  user = null; viewVersion++; clearInterval(qrTimer); await stopCamera();
  $('workspace').hidden = true; $('login').hidden = false; $('boot').hidden = true;
  $('password').value = ''; $('my-qr').removeAttribute('src');
  $('presence-rows').replaceChildren(); $('history-rows').replaceChildren();
  history = []; presence = [];
}
function navLink(key) { return `<a href="#${key}"><span class="nav-symbol" aria-hidden="true">${links[key][1]}</span>${links[key][0]}</a>`; }
async function enter(profile) {
  user = profile;
  $('login').hidden = true; $('workspace').hidden = false; $('boot').hidden = true;
  $('username').textContent = user.name;
  $('role').textContent = { admin: 'Administración', guard: 'Guardia', member: 'Comunidad' }[user.role];
  $('nav').innerHTML = allowed().map(navLink).join('');
  $('shortcuts').innerHTML = allowed().filter(k => k !== 'inicio').map(navLink).join('');
  await navigate();
}
function stat(label, value) { return `<div class="stat"><p>${escape(label)}</p><strong>${escape(value)}</strong></div>`; }
async function navigate() {
  if (!user) return;
  const version = ++viewVersion;
  let key = location.hash.slice(1) || 'inicio';
  if (!allowed().includes(key)) key = 'inicio';
  await stopCamera(); clearInterval(qrTimer);
  $('my-qr').hidden = true;
  for (const value of Object.values(views)) $(`${value}-view`).hidden = true;
  $(`${views[key]}-view`).hidden = false;
  $('sidebar').classList.remove('open'); $('menu').setAttribute('aria-expanded', 'false');
  $('title').textContent = links[key][0]; $('title').focus();
  $('status').textContent = 'Cargando…';
  document.querySelectorAll('#nav a').forEach(a => { if (a.hash === `#${key}`) a.setAttribute('aria-current', 'page'); else a.removeAttribute('aria-current'); });
  try {
    if (key === 'inicio') {
      $('stats').replaceChildren();
      const result = await api('/portal/summary');
      if (version !== viewVersion) return;
      $('stats').innerHTML = user.role === 'member'
        ? stat('Mi estado', result.inside ? 'Dentro' : 'Fuera') + stat('Último movimiento', date(result.lastTimestamp))
        : stat('Personas dentro', result.insideCount) + stat('Perfil activo', $('role').textContent) + stat('Consulta realizada', new Date().toLocaleTimeString('es-CL'));
    } else if (key === 'presence') {
      $('presence-rows').replaceChildren();
      const result = await api('/presence');
      if (version !== viewVersion) return;
      presence = result.data; renderPresence();
    } else if (key === 'history') {
      $('history-rows').replaceChildren();
      const result = await api('/portal/history');
      if (version !== viewVersion) return;
      history = result.data; renderHistory();
    } else if (key === 'qr') {
      const result = await api('/portal/qr');
      if (version !== viewVersion) return;
      $('credential-name').textContent = user.name;
      $('my-qr').src = result.qrDataUrl; $('my-qr').hidden = false;
      let checking = false, ticks = 0;
      const tick = async () => {
        if (checking || version !== viewVersion || !user) return;
        const left = Math.max(0, Math.ceil((result.expiresAt - Date.now()) / 1000));
        $('qr-expiry').textContent = left ? `Válido por ${left} segundos` : 'QR vencido. Genera uno nuevo.';
        if (!left || ++ticks % 3 === 0) {
          checking = true;
          try {
            const state = left ? await api('/portal/qr/status', { token: result.token }) : { renew: true };
            if (version === viewVersion && state.renew) {
              $('my-qr').hidden = true;
              await navigate();
            }
          } catch (error) {
            if (version === viewVersion) {
              $('my-qr').hidden = true;
              $('qr-expiry').textContent = error.message;
            }
          } finally { checking = false; }
        }
      };
      tick(); qrTimer = setInterval(tick, 1000);
    } else if (key === 'users') {
      const result = await api('/portal/users');
      if (version !== viewVersion) return;
      renderUsers(result.data);
    }
    if (version === viewVersion) $('status').textContent = '';
  } catch (error) { if (version === viewVersion) $('status').textContent = error.message; }
}
function renderUsers(rows) {
  $('user-rows').innerHTML = rows.map(v => `<tr><td>${escape(v.name)}</td><td>${escape(v.email || '—')}</td><td>${escape(v.role)}</td><td><span class="badge ${v.active ? '' : 'bad'}">${v.active ? 'Activo' : 'Desactivado'}</span></td><td>${v.uid ? `<button type="button" data-user-uid="${escape(v.uid)}" data-user-active="${v.active ? 'false' : 'true'}">${v.active ? 'Desactivar' : 'Activar'}</button>` : '—'}</td></tr>`).join('') || '<tr><td colspan="5" class="empty">No hay usuarios registrados.</td></tr>';
  document.querySelectorAll('[data-user-uid]').forEach(button => button.addEventListener('click', async () => {
    button.disabled = true;
    try { await api(`/portal/users/${encodeURIComponent(button.dataset.userUid)}`, { active: button.dataset.userActive === 'true' }, 'PATCH'); await navigate(); }
    catch (error) { $('status').textContent = error.message; button.disabled = false; }
  }));
}
function renderPresence() {
  const filter = $('presence-filter').value.toLowerCase();
  const rows = presence.filter(v => `${v.name} ${v.id}`.toLowerCase().includes(filter));
  $('presence-count').textContent = `${rows.length} de ${presence.length} personas dentro`;
  $('presence-rows').innerHTML = rows.map(v => `<tr><td>${escape(v.name)}</td><td>${escape(v.id)}</td><td>${escape(v.role)}</td><td>${escape(date(v.lastTimestamp))}</td></tr>`).join('') || '<tr><td colspan="4" class="empty">No hay personas que mostrar.</td></tr>';
}
function renderHistory() {
  const filter = $('history-filter').value.toLowerCase(), day = $('history-date').value, outcome = $('history-result').value;
  const localDay = timestamp => { const d = new Date(timestamp); return `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}-${String(d.getDate()).padStart(2,'0')}`; };
  const rows = history.filter(v => v.name.toLowerCase().includes(filter) && (!day || localDay(v.timestamp) === day) && (outcome === 'all' || v.authorized === (outcome === 'yes')));
  $('history-count').textContent = `${rows.length} registros · Consulta de hasta 500 eventos recientes`;
  $('history-rows').innerHTML = rows.map(v => `<tr><td>${escape(date(v.timestamp))}</td><td>${escape(v.name)}</td><td>${v.accessType === 'entry' ? 'Entrada' : v.accessType === 'exit' ? 'Salida' : '—'}</td><td><span class="badge ${v.authorized ? '' : 'bad'}">${v.authorized ? 'Autorizado' : 'Rechazado'}</span></td><td>${escape(v.reason === 'ok' ? 'Acceso válido' : v.reason)}</td></tr>`).join('') || '<tr><td colspan="5" class="empty">No hay movimientos para estos filtros.</td></tr>';
}
async function validate(value) {
  if (busy || !user) return;
  busy = true; $('validate-button').disabled = true;
  await stopCamera();
  $('scan-result').textContent = 'Validando…'; $('scan-result').removeAttribute('data-ok');
  try {
    let token = value.trim();
    if (/^https?:\/\//.test(token)) { const url = new URL(token); token = url.searchParams.get('token') || url.searchParams.get('qr') || token; }
    const result = await api('/validate', { qr: token, type: $('direction').value });
    $('scan-result').dataset.ok = 'true'; $('scan-result').textContent = `${result.message}: ${result.name || result.studentUid}`;
    $('qr-value').value = '';
  } catch (error) { $('scan-result').dataset.ok = 'false'; $('scan-result').textContent = error.message; }
  finally { busy = false; $('validate-button').disabled = false; }
}
$('login-form').addEventListener('submit', async event => {
  event.preventDefault(); $('login-button').disabled = true; $('login-error').textContent = '';
  try { const data = await api('/portal/login', { email: $('email').value.trim(), password: $('password').value }); $('password').value = ''; await enter(data.user); }
  catch (error) { $('login-error').textContent = error.message; }
  finally { $('login-button').disabled = false; }
});
$('reset-password').onclick = async () => {
  const email = $('email').value.trim() || window.prompt('Ingresa tu correo institucional:');
  if (!email) return;
  $('login-error').textContent = 'Procesando solicitud…';
  try { const result = await api('/portal/password-reset', { email }); $('login-error').textContent = result.message; }
  catch (error) { $('login-error').textContent = error.message; }
};
$('show-password').onchange = () => { $('password').type = $('show-password').checked ? 'text' : 'password'; };
$('logout').onclick = async () => {
  $('logout').disabled = true;
  try {
    await api('/portal/logout', {});
    for (const key of ['idToken','admin_user','admin_uid','guard_auth_token','guard_auth_guardid']) { localStorage.removeItem(key); sessionStorage.removeItem(key); }
    await showLogin(); location.hash = '';
  } catch (error) { $('status').textContent = error.message; }
  finally { $('logout').disabled = false; }
};
$('menu').onclick = () => { const open = $('sidebar').classList.toggle('open'); $('menu').setAttribute('aria-expanded', String(open)); };
$('refresh').onclick = navigate; $('renew-qr').onclick = navigate;
$('presence-filter').oninput = renderPresence;
for (const id of ['history-filter','history-date','history-result']) $(id).oninput = renderHistory;
$('scan-form').onsubmit = event => { event.preventDefault(); validate($('qr-value').value); };
$('user-form').onsubmit = async event => {
  event.preventDefault(); $('user-form-status').textContent = 'Creando usuario…';
  try { await api('/portal/users', { name: $('user-name').value.trim(), email: $('user-email').value.trim(), password: $('user-password').value, role: $('user-role').value }); $('user-form').reset(); $('user-form-status').textContent = 'Usuario creado correctamente.'; await navigate(); }
  catch (error) { $('user-form-status').textContent = error.message; }
};
$('stop-camera').onclick = stopCamera;
$('start-camera').onclick = async () => {
  $('start-camera').disabled = true; $('scan-result').textContent = '';
  const version = viewVersion;
  try {
    if (!window.Html5Qrcode) throw new Error('El lector QR no pudo cargarse. Actualiza la página.');
    scanner ||= new Html5Qrcode('reader');
    await scanner.start({ facingMode: 'environment' }, { fps: 10, qrbox: { width: 220, height: 220 } }, value => { if (scanning) validate(value); });
    scanning = true; $('stop-camera').disabled = false;
    if (version !== viewVersion || !user) await stopCamera();
  } catch { $('scan-result').textContent = 'No se pudo abrir la cámara. Revisa los permisos y usa HTTPS o localhost.'; $('start-camera').disabled = false; }
};
window.addEventListener('hashchange', navigate);
window.addEventListener('pagehide', () => { stopCamera(); clearInterval(qrTimer); });
window.addEventListener('pageshow', event => { if (event.persisted) location.reload(); });
api('/portal/me').then(data => enter(data.user)).catch(async error => { await showLogin(); if (!error.message.includes('Inicia sesion')) $('login-error').textContent = error.message; });
