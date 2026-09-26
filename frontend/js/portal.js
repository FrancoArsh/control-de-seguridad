/* Portal navigation is driven by the server-authorized profile. */
const $ = id => document.getElementById(id);
let user, scanner, scanning = false, busy = false, viewVersion = 0, qrTimer;
let presence = [], history = [], guards = [];
let filteredHistory = [];
let editingUser;
const links = { inicio: ['Inicio', '⌂'], scan: ['Escanear QR', '▣'], presence: ['Personas dentro', '◉'], history: ['Historial', '≡'], qr: ['Mi código QR', '▦'], users: ['Usuarios', '♙'], guards: ['Guardias', '♜'] };
const views = { inicio: 'home', scan: 'scan', presence: 'presence', history: 'history', qr: 'qr', users: 'users', guards: 'guards' };
const allowed = () => user?.role === 'member' ? ['inicio', 'qr', 'history'] : user?.role === 'guard' ? ['inicio', 'scan', 'history'] : ['inicio', 'presence', 'history', 'users', 'guards'];
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
  history = []; presence = []; guards = [];
}
function navLink(key) { return `<a href="#${key}"><span class="nav-symbol" aria-hidden="true">${links[key][1]}</span>${links[key][0]}</a>`; }
async function enter(profile) {
  user = profile;
  $('login').hidden = true; $('workspace').hidden = false; $('boot').hidden = true;
  $('workspace').dataset.role = user.role;
  $('guard-shift-panel').hidden = user.role !== 'guard';
  $('report-actions').hidden = false;
  $('download-pdf').hidden = user.role !== 'admin';
  $('username').textContent = user.name;
  $('role').textContent = { admin: 'Administración', guard: 'Guardia operativa', member: 'Comunidad' }[user.role];
  $('portal-type').textContent = user.role === 'guard' ? 'Portal de Guardia' : user.role === 'admin' ? 'Panel de Administración' : 'Portal de acceso';
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
        : user.role === 'guard' ? stat('Guardia', user.name) + stat('Identificador', user.id)
        : stat('Personas dentro', result.insideCount) + stat('Perfil activo', $('role').textContent) + stat('Consulta realizada', new Date().toLocaleTimeString('es-CL'));
      if (user.role === 'guard') await loadGuardShift();
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
    } else if (key === 'guards') {
      const result = await api('/portal/guard-report');
      if (version !== viewVersion) return;
      guards = result.data; renderGuards();
    }
    if (version === viewVersion) $('status').textContent = '';
  } catch (error) { if (version === viewVersion) $('status').textContent = error.message; }
}
function renderUsers(rows) {
  $('user-rows').innerHTML = rows.map(v => `<tr><td>${escape(v.name)}</td><td>${escape(v.email || 'Sin correo asociado')}</td><td>${escape(v.role)}</td><td><span class="badge ${v.active ? '' : 'bad'}">${v.active ? 'Activo' : 'Desactivado'}</span></td><td>${v.role === 'member' ? `<button type="button" data-qr-id="${escape(v.id)}">Ver QR</button> ` : ''}${v.uid ? `<button type="button" title="${v.active ? 'Impide el acceso de esta cuenta' : 'Permite nuevamente el acceso de esta cuenta'}" data-user-uid="${escape(v.uid)}" data-user-active="${v.active ? 'false' : 'true'}">${v.active ? 'Desactivar' : 'Activar'}</button>` : 'Sin cuenta'}</td></tr>`).join('') || '<tr><td colspan="5" class="empty">No hay usuarios registrados.</td></tr>';
  Array.from($('user-rows').rows).forEach((tr, index) => {
    if (!rows[index]) return;
    const button = document.createElement('button'); button.textContent = 'Editar'; button.type = 'button';
    button.onclick = () => {
      editingUser = rows[index];
      $('edit-name').value = editingUser.name; $('edit-sede').value = editingUser.sede || ''; $('edit-type').value = editingUser.tipoUsuario || '';
      $('edit-status').textContent = ''; $('edit-dialog').showModal();
    };
    tr.lastElementChild.append(button);
  });
  document.querySelectorAll('[data-qr-id]').forEach(button => button.addEventListener('click', async () => {
    button.disabled = true;
    try { const result = await api(`/portal/student-qr/${encodeURIComponent(button.dataset.qrId)}`); const popup = window.open('', '_blank', 'noopener,noreferrer'); if (popup) popup.document.write(`<title>QR de ${escape(result.name)}</title><h1>${escape(result.name)}</h1><img src="${result.qrDataUrl}" alt="Código QR de acceso" width="320" height="320"><p>Válido hasta ${escape(date(result.expiresAt))}</p>`); }
    catch (error) { $('status').textContent = error.message; } finally { button.disabled = false; }
  }));
  document.querySelectorAll('[data-user-uid]').forEach(button => button.addEventListener('click', async () => {
    button.disabled = true;
    try { await api(`/portal/users/${encodeURIComponent(button.dataset.userUid)}`, { active: button.dataset.userActive === 'true' }, 'PATCH'); await navigate(); }
    catch (error) { $('status').textContent = error.message; button.disabled = false; }
  }));
}
function renderPresence() {
  const filter = $('presence-filter').value.toLowerCase(), sede = $('presence-sede').value.toLowerCase(), role = $('presence-role').value.toLowerCase(), day = $('presence-date').value;
  const localDay = timestamp => { const d = new Date(timestamp); return `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}-${String(d.getDate()).padStart(2,'0')}`; };
  const rows = presence.filter(v => `${v.name} ${v.id}`.toLowerCase().includes(filter) && (!sede || String(v.sede || '').toLowerCase().includes(sede)) && (!role || `${v.role} ${v.tipoUsuario}`.toLowerCase().includes(role)) && (!day || localDay(v.lastTimestamp) === day));
  $('presence-count').textContent = `${rows.length} de ${presence.length} personas dentro`;
  $('presence-rows').innerHTML = rows.map(v => `<tr><td>${escape(v.name)}</td><td>${escape(v.id)}</td><td>${escape(v.sede || 'Sin sede')}</td><td>${escape(v.tipoUsuario || v.role || 'Sin tipo')}</td><td>${v.lastAccessType === 'entry' ? 'Entrada' : 'Salida'}</td><td>${escape(date(v.lastTimestamp))}</td></tr>`).join('') || '<tr><td colspan="6" class="empty">No hay personas que mostrar.</td></tr>';
}
function renderHistory() {
  const filter = $('history-filter').value.toLowerCase(), day = $('history-date').value, sede = $('history-sede').value.toLowerCase(), role = $('history-role').value.toLowerCase(), outcome = $('history-result').value;
  const localDay = timestamp => { const d = new Date(timestamp); return `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}-${String(d.getDate()).padStart(2,'0')}`; };
  const rows = history.filter(v => `${v.name} ${v.id}`.toLowerCase().includes(filter) && (!day || localDay(v.timestamp) === day) && (!sede || String(v.sede || '').toLowerCase().includes(sede)) && (!role || `${v.tipoUsuario} ${v.validatedByRole}`.toLowerCase().includes(role)) && (outcome === 'all' || v.authorized === (outcome === 'yes')));
  $('history-count').textContent = `${rows.length} registros · Consulta de hasta 500 eventos recientes`;
  filteredHistory = rows;
  $('history-rows').innerHTML = rows.map(v => `<tr><td>${escape(date(v.timestamp))}</td><td>${escape(v.name)}<small class="subvalue">${escape(v.id)}</small></td><td>${escape(v.sede || 'Sin sede')}</td><td>${escape(v.tipoUsuario || 'Sin tipo')}</td><td>${v.accessType === 'entry' ? 'Entrada' : v.accessType === 'exit' ? 'Salida' : '—'}</td><td><span class="badge ${v.authorized ? '' : 'bad'}">${v.authorized ? 'Autorizado' : 'Rechazado'}</span></td><td>${escape(v.reason === 'ok' ? 'Acceso válido' : v.reason)}</td><td>${escape(v.validatedBy || 'Sin registrar')}</td></tr>`).join('') || '<tr><td colspan="8" class="empty">No hay movimientos para estos filtros.</td></tr>';
}
function renderGuards() {
  $('guard-rows').innerHTML = guards.map(v => `<tr><td>${escape(v.name)}<small class="subvalue">${escape(v.id)}</small></td><td>${escape(v.email || 'Sin correo asociado')}</td><td>${v.shiftActive ? '<span class="badge">Activo</span>' : v.shiftId ? '<span class="badge bad">Finalizado</span>' : 'Sin turno'}</td><td>${escape(date(v.startTimestamp))}</td><td>${escape(date(v.endTimestamp))}</td><td>${escape(v.approvedAccesses)}</td><td>${escape(v.rejectedAccesses)}</td><td>${escape(v.totalAccesses)}</td></tr>`).join('') || '<tr><td colspan="8" class="empty">No hay guardias registrados.</td></tr>';
}
async function loadGuardShift() {
  const panel = $('guard-shift-panel');
  panel.hidden = false;
  try {
    const result = await api('/portal/guard/shift');
    $('shift-status').textContent = result.active ? `Turno activo desde ${date(result.shift.startTimestamp)}. Puedes validar accesos.` : 'Sin turno activo. Inicia turno para validar accesos.';
    $('start-shift').disabled = result.active;
    $('end-shift').disabled = !result.active;
    $('shift-title').textContent = result.active ? 'Turno activo' : 'Turno cerrado';
  } catch (error) { $('shift-status').textContent = error.message; }
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
    const movement = result.accessType === 'exit' ? 'Salida' : 'Entrada';
    $('scan-result').dataset.ok = 'true'; $('scan-result').textContent = `${movement} autorizada: ${result.name || result.studentUid}`;
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
$('edit-cancel').onclick = () => $('edit-dialog').close();
$('edit-form').onsubmit = async event => {
  event.preventDefault();
  const submit = event.submitter; submit.disabled = true;
  try {
    await api(`/portal/users/${editingUser.role}/${encodeURIComponent(editingUser.id)}/profile`, { name: $('edit-name').value, sede: $('edit-sede').value, tipoUsuario: $('edit-type').value }, 'PATCH');
    $('edit-dialog').close(); await navigate();
  } catch (error) { $('edit-status').textContent = error.message; }
  finally { submit.disabled = false; }
};
$('download-csv').onclick = async () => {
  try {
    const { historyCsv } = await import('/js/report.mjs');
    const url = URL.createObjectURL(new Blob([historyCsv(filteredHistory)], { type: 'text/csv;charset=utf-8' }));
    const link = document.createElement('a');
    link.href = url; link.download = 'historial-accesos.csv'; link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  } catch { $('status').textContent = 'No se pudo exportar el historial.'; }
};
$('download-pdf').onclick = async () => {
  try {
    const response = await fetch('/portal/history.pdf', { credentials: 'same-origin', headers: { 'X-Portal-Request': '1' }, cache: 'no-store' });
    if (!response.ok) throw new Error('No se pudo exportar el PDF.');
    const url = URL.createObjectURL(await response.blob());
    const link = document.createElement('a'); link.href = url; link.download = 'historial-accesos.pdf'; link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  } catch (error) { $('status').textContent = error.message; }
};
for (const id of ['presence-filter','presence-sede','presence-role','presence-date']) $(id).oninput = renderPresence;
for (const id of ['history-filter','history-date','history-sede','history-role','history-result']) $(id).oninput = renderHistory;
document.querySelectorAll('.direction-choice').forEach(button => button.onclick = () => {
  const direction = button.dataset.direction;
  $('direction').value = direction;
  document.querySelectorAll('.direction-choice').forEach(item => { const active = item === button; item.classList.toggle('active', active); item.setAttribute('aria-pressed', String(active)); });
  $('validate-button').textContent = direction === 'exit' ? 'Validar salida' : 'Validar entrada';
});
$('scan-form').onsubmit = event => { event.preventDefault(); validate($('qr-value').value); };
$('user-form').onsubmit = async event => {
  event.preventDefault(); $('user-form-status').textContent = 'Creando usuario…';
  try { await api('/portal/users', { name: $('user-name').value.trim(), email: $('user-email').value.trim(), password: $('user-password').value, role: $('user-role').value }); $('user-form').reset(); $('user-form-status').textContent = 'Usuario creado correctamente.'; await navigate(); }
  catch (error) { $('user-form-status').textContent = error.message; }
};
$('start-shift').onclick = async () => {
  $('start-shift').disabled = true;
  try { await api('/portal/guard/shift/start', {}); await loadGuardShift(); }
  catch (error) { $('shift-status').textContent = error.message; $('start-shift').disabled = false; }
};
$('end-shift').onclick = async () => {
  $('end-shift').disabled = true;
  try { await api('/portal/guard/shift/end', {}); await loadGuardShift(); }
  catch (error) { $('shift-status').textContent = error.message; $('end-shift').disabled = false; }
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
