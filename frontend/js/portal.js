/* Portal navigation is driven by the server-authorized profile. */
const $ = id => document.getElementById(id);
let user, scanner, scanning = false, busy = false, viewVersion = 0, qrTimer;
let cameraStarting = false, cameraGeneration = 0;
let presence = [], history = [], guards = [];
let filteredHistory = [];
let guardCursors = [''], guardPage = 0, guardNext = null, guardTo = 0, guardRequest = 0;
let historyCursors = [''], historyPage = 0, historyNext = null, historyQuery = '', historyRequest = 0, historyTimer;
let editingUser;
let adminQrRequest = 0, adminQrTimer, creatingUser = false;
document.body.insertAdjacentHTML('beforeend', '<dialog id="admin-qr-dialog" aria-labelledby="admin-qr-title"><h2 id="admin-qr-title">Credencial de acceso</h2><img id="admin-qr-image" width="240" height="240" alt="Código QR de acceso" hidden><p id="admin-qr-status" role="status"></p><button id="admin-qr-close" type="button">Cerrar</button></dialog>');
function clearAdminQr() {
  adminQrRequest++; clearInterval(adminQrTimer);
  $('admin-qr-image').hidden = true; $('admin-qr-image').removeAttribute('src');
}
$('admin-qr-close').onclick = () => $('admin-qr-dialog').close();
$('admin-qr-dialog').addEventListener('close', clearAdminQr);
$('history-count').setAttribute('aria-live', 'polite');
$('history-count').insertAdjacentHTML('afterend', '<nav class="history-pagination" aria-label="Páginas del historial"><button id="history-prev" type="button" title="Página anterior" aria-label="Página anterior" disabled>←</button><button id="history-next" type="button" title="Página siguiente" aria-label="Página siguiente" disabled>→</button></nav>');
$('download-csv').textContent = 'CSV de esta página';
$('guards-view').querySelector('.section-intro').insertAdjacentHTML('afterend', '<div id="guard-stats" class="stats"></div>');
$('guards-view').querySelector('.table-scroll').insertAdjacentHTML('beforebegin', '<p id="guard-count" role="status"></p><nav class="history-pagination" aria-label="Páginas de turnos"><button id="guard-prev" type="button" aria-label="Página anterior" title="Página anterior" disabled>←</button><button id="guard-next" type="button" aria-label="Página siguiente" title="Página siguiente" disabled>→</button></nav>');
$('guard-prev').onclick = () => loadGuardReport(false, guardPage - 1);
$('guard-next').onclick = () => { if (guardNext) { guardCursors[guardPage + 1] = guardNext; loadGuardReport(false, guardPage + 1); } };
$('download-pdf').textContent = 'PDF de esta página';
const historyFilters = document.createElement('details');
historyFilters.className = 'history-filter-panel';
historyFilters.open = !matchMedia('(max-width: 650px)').matches;
matchMedia('(max-width: 650px)').addEventListener('change', event => { historyFilters.open = !event.matches; });
historyFilters.innerHTML = '<summary>Filtros del historial</summary>';
const filterFields = $('history-view').querySelector('.filters');
filterFields.before(historyFilters); historyFilters.append(filterFields);
$('history-view').insertAdjacentHTML('beforeend', '<div id="history-mobile" class="history-mobile"></div>');
$('status').insertAdjacentHTML('afterend', '<p id="connection-status" role="status" hidden></p>');
document.querySelectorAll('.table-scroll').forEach(element => {
  element.tabIndex = 0;
  element.setAttribute('role', 'region');
  element.setAttribute('aria-label', 'Tabla de registros');
});
const links = { inicio: ['Inicio', '⌂'], scan: ['Escanear QR', '▣'], presence: ['Personas dentro', '◉'], history: ['Historial', '≡'], qr: ['Mi código QR', '▦'], users: ['Usuarios', '♙'], guards: ['Guardias', '♜'] };
const views = { inicio: 'home', scan: 'scan', presence: 'presence', history: 'history', qr: 'qr', users: 'users', guards: 'guards' };
const allowed = () => user?.role === 'member' ? ['inicio', 'qr', 'history'] : user?.role === 'guard' ? ['inicio', 'scan', 'history'] : ['inicio', 'presence', 'history', 'users', 'guards'];
const date = value => value ? new Date(value).toLocaleString('es-CL') : 'Sin registros';
const escape = value => String(value ?? '').replace(/[&<>"']/g, v => ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;' })[v]);

async function api(path, body, method) {
  const requestUser = user;
  const verb = method || (body === undefined ? 'GET' : 'POST');
  const controller = new AbortController(), timeout = setTimeout(() => controller.abort(), 20000);
  let response, data;
  try {
    response = await fetch(path, { method: verb, credentials: 'same-origin', headers: { 'Content-Type': 'application/json', 'X-Portal-Request': '1' }, body: body === undefined ? undefined : JSON.stringify(body), cache: 'no-store', signal: controller.signal });
    data = await response.json();
  } catch {
    throw new Error(verb === 'GET' ? 'No se pudo consultar el servidor. Revisa la conexión y vuelve a intentar.' : 'Sin confirmación del servidor. Consulta el estado antes de repetir la operación.');
  } finally { clearTimeout(timeout); }
  if (!response.ok) {
    if (response.status === 401 && path !== '/portal/login' && requestUser === user) await showLogin();
    throw new Error(data.error || 'No fue posible completar la solicitud.');
  }
  return data;
}
async function stopCamera() {
  cameraGeneration++;
  if (scanner && scanning) {
    scanning = false;
    try { await scanner.stop(); } catch {
      document.querySelectorAll('#reader video').forEach(video => video.srcObject?.getTracks().forEach(track => track.stop()));
      scanner = null; $('reader').replaceChildren();
    }
  }
  $('stop-camera').disabled = true;
  $('start-camera').disabled = cameraStarting;
}
async function showLogin() {
  guardRequest++; guardCursors = ['']; guardNext = null;
  clearAdminQr(); $('admin-qr-dialog').close(); $('edit-dialog').close(); editingUser = null;
  historyRequest++; clearTimeout(historyTimer); filteredHistory = []; historyQuery = '';
  user = null; viewVersion++; clearInterval(qrTimer); await stopCamera();
  $('workspace').hidden = true; $('login').hidden = false; $('boot').hidden = true;
  $('password').value = ''; $('my-qr').removeAttribute('src');
  $('presence-rows').replaceChildren(); $('history-rows').replaceChildren();
  $('history-mobile').replaceChildren();
  $('user-rows').replaceChildren(); $('guard-rows').replaceChildren();
  $('guard-stats').replaceChildren();
  $('scan-result').textContent = ''; $('qr-value').value = ''; $('user-password').value = '';
  history = []; presence = []; guards = [];
}
function navLink(key) { return `<a href="#${key}"><span class="nav-symbol" aria-hidden="true">${links[key][1]}</span>${links[key][0]}</a>`; }
async function enter(profile) {
  user = profile;
  $('login').hidden = true; $('workspace').hidden = false; $('boot').hidden = true;
  $('workspace').dataset.role = user.role;
  $('guard-shift-panel').hidden = user.role !== 'guard';
  $('guard-exception-panel').hidden = user.role !== 'guard';
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
  clearAdminQr(); $('admin-qr-dialog').close();
  const version = ++viewVersion;
  let key = location.hash.slice(1) || 'inicio';
  if (!allowed().includes(key)) key = 'inicio';
  await stopCamera(); clearInterval(qrTimer);
  $('my-qr').hidden = true;
  for (const value of Object.values(views)) $(`${value}-view`).hidden = true;
  $(`${views[key]}-view`).hidden = false;
  closeMenu();
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
        : stat('Personas dentro', result.insideCount) + guardStats(result.guardCounts);
      if (user.role === 'guard') await loadGuardShift();
    } else if (key === 'presence') {
      $('presence-rows').replaceChildren();
      const result = await api('/presence');
      if (version !== viewVersion) return;
      presence = result.data; renderPresence();
    } else if (key === 'history') {
      await loadHistory(true);
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
      await loadGuardReport(true);
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
    const request = ++adminQrRequest, version = viewVersion;
    button.disabled = true;
    clearInterval(adminQrTimer); $('admin-qr-image').hidden = true; $('admin-qr-image').removeAttribute('src');
    $('admin-qr-title').textContent = 'Credencial de acceso'; $('admin-qr-status').textContent = 'Cargando…';
    if (!$('admin-qr-dialog').open) $('admin-qr-dialog').showModal();
    try {
      const result = await api(`/portal/student-qr/${encodeURIComponent(button.dataset.qrId)}`);
      if (request !== adminQrRequest || version !== viewVersion || user?.role !== 'admin') return;
      if (!/^data:image\/png;base64,/.test(result.qrDataUrl) || !Number.isFinite(result.expiresAt)) throw new Error('Credencial no válida.');
      $('admin-qr-title').textContent = result.name || 'Credencial de acceso';
      $('admin-qr-image').src = result.qrDataUrl;
      const tick = () => {
        const seconds = Math.max(0, Math.ceil((result.expiresAt - Date.now()) / 1000));
        $('admin-qr-image').hidden = seconds === 0;
        $('admin-qr-status').textContent = seconds ? `Válido por ${seconds} segundos` : 'QR vencido. Cierra esta ventana y solicita uno nuevo.';
        if (!seconds) { clearInterval(adminQrTimer); $('admin-qr-image').removeAttribute('src'); }
      };
      tick(); if (result.expiresAt > Date.now()) adminQrTimer = setInterval(tick, 1000);
    } catch (error) { if (request === adminQrRequest) $('admin-qr-status').textContent = error.message; }
    finally { button.disabled = false; }
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
async function loadHistory(reset = false, target = historyPage) {
  const request = ++historyRequest, version = viewVersion;
  if (reset) { historyCursors = ['']; target = 0; }
  const params = reset ? new URLSearchParams({ limit: '100', search: $('history-filter').value, sede: $('history-sede').value, role: $('history-role').value, outcome: $('history-result').value, to: String(Date.now()) }) : new URLSearchParams(historyQuery);
  if (reset && $('history-date').value) {
    const start = new Date(`${$('history-date').value}T00:00:00`), end = new Date(start);
    end.setDate(end.getDate() + 1);
    params.set('from', String(start.getTime())); params.set('to', String(end.getTime() - 1));
  }
  params.delete('cursor');
  if (historyCursors[target]) params.set('cursor', historyCursors[target]);
  for (const id of ['history-prev', 'history-next', 'download-csv', 'download-pdf']) $(id).disabled = true;
  $('history-count').textContent = 'Cargando movimientos…';
  try {
    const result = await api(`/portal/history?${params}`);
    if (request !== historyRequest || version !== viewVersion || !user) return;
    historyQuery = params.toString(); historyPage = target; historyNext = result.nextCursor;
    history = result.data; renderHistory();
    $('history-prev').disabled = target === 0; $('history-next').disabled = !historyNext;
    $('download-csv').disabled = $('download-pdf').disabled = !history.length;
  } catch (error) {
    if (request === historyRequest && version === viewVersion) {
      history = []; filteredHistory = []; $('history-rows').replaceChildren();
      $('history-mobile').replaceChildren();
      $('history-count').textContent = error.message;
    }
  }
}
function renderHistory() {
  const rows = history;
  $('history-count').textContent = `Página ${historyPage + 1} · ${rows.length} ${rows.length === 1 ? 'registro' : 'registros'}${!rows.length && historyNext ? ' · Hay más movimientos por consultar' : ''}`;
  filteredHistory = rows;
  $('history-mobile').innerHTML = rows.map(v => `<details class="history-item"><summary><span><strong>${escape(v.name)}</strong><time>${escape(date(v.timestamp))}</time></span><span class="badge ${v.authorized ? '' : 'bad'}">${v.authorized ? 'Autorizado' : 'Rechazado'}</span></summary><dl><dt>Identificador</dt><dd>${escape(v.id)}</dd><dt>Movimiento</dt><dd>${v.accessType === 'entry' ? 'Entrada' : v.accessType === 'exit' ? 'Salida' : 'Sin movimiento'}</dd><dt>Sede</dt><dd>${escape(v.sede)}</dd><dt>Tipo</dt><dd>${escape(v.tipoUsuario)}</dd><dt>Motivo</dt><dd>${escape(v.reason === 'ok' ? 'Acceso válido' : v.reason)}</dd><dt>Validó</dt><dd>${escape(v.validatedBy)}</dd></dl></details>`).join('') || '<p class="empty">No hay movimientos para mostrar en esta página.</p>';
  $('history-rows').innerHTML = rows.map(v => `<tr><td>${escape(date(v.timestamp))}</td><td>${escape(v.name)}<small class="subvalue">${escape(v.id)}</small></td><td>${escape(v.sede || 'Sin sede')}</td><td>${escape(v.tipoUsuario || 'Sin tipo')}</td><td>${v.accessType === 'entry' ? 'Entrada' : v.accessType === 'exit' ? 'Salida' : '—'}</td><td><span class="badge ${v.authorized ? '' : 'bad'}">${v.authorized ? 'Autorizado' : 'Rechazado'}</span></td><td>${escape(v.reason === 'ok' ? 'Acceso válido' : v.reason)}</td><td>${escape(v.validatedBy || 'Sin registrar')}</td></tr>`).join('') || '<tr><td colspan="8" class="empty">No hay movimientos para estos filtros.</td></tr>';
}
async function loadGuardReport(reset = false, target = guardPage) {
  const request = ++guardRequest, version = viewVersion;
  if (reset) { guardCursors = ['']; target = 0; guardTo = Date.now(); }
  if (target < 0) return;
  const params = new URLSearchParams({ limit: '5', to: String(guardTo) });
  if (guardCursors[target]) params.set('cursor', guardCursors[target]);
  $('guard-prev').disabled = $('guard-next').disabled = true;
  $('guard-count').textContent = 'Cargando turnos…';
  $('guard-stats').replaceChildren();
  $('exception-form').reset(); $('exception-status').textContent = '';
  try {
    const result = await api(`/portal/guard-report?${params}`);
    if (request !== guardRequest || version !== viewVersion || !user) return;
    guards = result.data; guardPage = target; guardNext = result.nextCursor;
    $('guard-stats').innerHTML = guardStats(result.guardCounts);
    renderGuards();
    $('guard-count').textContent = `Página ${target + 1} · ${guards.length} turnos${guards.some(v => v.countsComplete === false) ? ' · Conteo parcial: se muestran mínimos, no totales definitivos.' : ''}`;
    $('guard-prev').disabled = target === 0; $('guard-next').disabled = !guardNext;
  } catch (error) {
    if (request === guardRequest && version === viewVersion) {
      guards = []; $('guard-rows').replaceChildren(); $('guard-count').textContent = error.message;
    }
  }
}
function renderGuards() {
  guards = guards.map(v => v.countsComplete === false ? { ...v, approvedAccesses: `≥ ${v.approvedAccesses}`, rejectedAccesses: `≥ ${v.rejectedAccesses}`, totalAccesses: `≥ ${v.totalAccesses} (parcial)` } : v);
  $('guard-rows').innerHTML = guards.map(v => `<tr><td>${escape(v.name)}<small class="subvalue">${escape(v.id)}</small></td><td>${escape(v.email || 'Sin correo asociado')}</td><td>${v.shiftActive ? '<span class="badge">Activo</span>' : v.shiftId ? '<span class="badge bad">Finalizado</span>' : 'Sin turno'}</td><td>${escape(date(v.startTimestamp))}</td><td>${escape(date(v.endTimestamp))}</td><td>${escape(v.approvedAccesses)}</td><td>${escape(v.rejectedAccesses)}</td><td>${escape(v.totalAccesses)}</td></tr>`).join('') || '<tr><td colspan="8" class="empty">No hay guardias registrados.</td></tr>';
}
function guardStats(counts) {
  return stat('Guardias registrados', counts?.total ?? 'No disponible')
    + stat('Guardias activos', counts?.active ?? 'No disponible')
    + stat('Guardias inactivos', counts?.inactive ?? 'No disponible');
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
  if (!navigator.onLine) { $('scan-result').removeAttribute('data-ok'); $('scan-result').textContent = 'Sin conexión. No se ha enviado la validación.'; return; }
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
function closeMenu(restoreFocus = false) {
  $('sidebar').classList.remove('open'); $('menu').setAttribute('aria-expanded', 'false');
  if (restoreFocus) $('menu').focus();
}
$('menu').onclick = () => {
  const open = $('sidebar').classList.toggle('open'); $('menu').setAttribute('aria-expanded', String(open));
  if (open) $('nav').querySelector('a')?.focus();
};
document.addEventListener('keydown', event => { if (event.key === 'Escape' && $('sidebar').classList.contains('open')) closeMenu(true); });
document.addEventListener('click', event => {
  if (!$('sidebar').contains(event.target) && !$('menu').contains(event.target)) closeMenu();
});
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
    link.href = url; link.download = `historial-pagina-${historyPage + 1}.csv`; link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  } catch { $('status').textContent = 'No se pudo exportar el historial.'; }
};
$('download-pdf').onclick = async () => {
  try {
    const response = await fetch(`/portal/history.pdf?${historyQuery}`, { credentials: 'same-origin', headers: { 'X-Portal-Request': '1' }, cache: 'no-store' });
    if (!response.ok) throw new Error('No se pudo exportar el PDF.');
    const url = URL.createObjectURL(await response.blob());
    const link = document.createElement('a'); link.href = url; link.download = 'historial-accesos.pdf'; link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  } catch (error) { $('status').textContent = error.message; }
};
for (const id of ['presence-filter','presence-sede','presence-role','presence-date']) $(id).oninput = renderPresence;
for (const id of ['history-filter','history-date','history-sede','history-role','history-result']) $(id).oninput = () => {
  clearTimeout(historyTimer); historyRequest++;
  for (const control of ['history-prev', 'history-next', 'download-csv', 'download-pdf']) $(control).disabled = true;
  historyTimer = setTimeout(() => { if (user && !$('history-view').hidden) loadHistory(true); }, 350);
};
$('history-prev').onclick = () => loadHistory(false, historyPage - 1);
$('history-next').onclick = () => { historyCursors[historyPage + 1] = historyNext; loadHistory(false, historyPage + 1); };
document.querySelectorAll('.direction-choice').forEach(button => button.onclick = () => {
  const direction = button.dataset.direction;
  $('direction').value = direction;
  document.querySelectorAll('.direction-choice').forEach(item => { const active = item === button; item.classList.toggle('active', active); item.setAttribute('aria-pressed', String(active)); });
  $('validate-button').textContent = direction === 'exit' ? 'Validar salida' : 'Validar entrada';
});
$('scan-form').onsubmit = event => { event.preventDefault(); validate($('qr-value').value); };
$('user-form').onsubmit = async event => {
  event.preventDefault(); if (creatingUser) return;
  creatingUser = true;
  const submit = $('user-form').querySelector('[type=submit]'); submit.disabled = true;
  $('user-form-status').textContent = 'Creando usuario…';
  try { await api('/portal/users', { name: $('user-name').value.trim(), email: $('user-email').value.trim(), password: $('user-password').value, role: $('user-role').value }); $('user-form').reset(); $('user-form-status').textContent = 'Usuario creado correctamente.'; await navigate(); }
  catch (error) { $('user-form-status').textContent = error.message; }
  finally { creatingUser = false; submit.disabled = false; }
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
$('exception-form').onsubmit = async event => {
  event.preventDefault();
  const submit = $('exception-form').querySelector('[type=submit]');
  submit.disabled = true; $('exception-status').textContent = 'Registrando excepción…';
  try {
    const result = await api('/portal/guard/exception', { userId: $('exception-user-id').value.trim(), type: $('exception-type').value, reason: $('exception-reason').value.trim() });
    $('exception-status').textContent = `${result.accessType === 'entry' ? 'Entrada' : 'Salida'} manual registrada para ${result.name || result.studentUid}.`;
    $('exception-form').reset();
  } catch (error) { $('exception-status').textContent = error.message; }
  finally { submit.disabled = false; }
};
$('stop-camera').onclick = stopCamera;
$('start-camera').onclick = async () => {
  if (cameraStarting || scanning || user?.role !== 'guard') return;
  if (!window.isSecureContext) { $('scan-result').textContent = 'La cámara requiere una conexión HTTPS segura.'; return; }
  if (!navigator.mediaDevices?.getUserMedia) { $('scan-result').textContent = 'Este navegador no permite acceder a la cámara. Puedes utilizar el campo de código QR.'; return; }
  cameraStarting = true;
  const generation = ++cameraGeneration;
  $('start-camera').disabled = true; $('scan-result').textContent = '';
  const version = viewVersion;
  try {
    if (!window.Html5Qrcode) throw new Error('El lector QR no pudo cargarse. Actualiza la página.');
    scanner ||= new Html5Qrcode('reader');
    await scanner.start({ facingMode: 'environment' }, { fps: 10, qrbox: (width, height) => { const side = Math.max(50, Math.min(240, Math.floor(Math.min(width, height) * 0.7))); return { width: side, height: side }; } }, value => { if (scanning && generation === cameraGeneration && !document.hidden) validate(value); });
    scanning = true; $('stop-camera').disabled = false;
    const video = $('reader').querySelector('video');
    if (video) { video.setAttribute('playsinline', ''); video.muted = true; }
    if (version !== viewVersion || !user || document.hidden || generation !== cameraGeneration) await stopCamera();
  } catch (error) {
    if (version === viewVersion && generation === cameraGeneration) {
      const detail = String(error?.name || error || '');
      $('scan-result').textContent = /NotAllowed|PermissionDenied/.test(detail) ? 'Permiso de cámara denegado. Revisa los permisos del navegador.' : /NotFound|DevicesNotFound/.test(detail) ? 'No se encontró una cámara disponible.' : /NotReadable|TrackStart/.test(detail) ? 'La cámara está ocupada o no se puede iniciar. Cierra otras aplicaciones que la utilicen.' : 'No se pudo abrir la cámara. Puedes utilizar el campo de código QR.';
    }
  } finally { cameraStarting = false; $('start-camera').disabled = scanning; }
};
function updateConnection() {
  $('connection-status').hidden = navigator.onLine;
  $('connection-status').textContent = navigator.onLine ? '' : 'Sin conexión. No se pueden confirmar accesos ni cambios.';
}
window.addEventListener('offline', updateConnection);
window.addEventListener('online', updateConnection);
updateConnection();
document.addEventListener('visibilitychange', () => {
  if (document.hidden) { stopCamera(); clearInterval(qrTimer); $('my-qr').hidden = true; clearAdminQr(); $('admin-qr-dialog').close(); }
  else if (user && location.hash === '#qr') navigate();
});
window.addEventListener('hashchange', navigate);
window.addEventListener('pagehide', () => { stopCamera(); clearInterval(qrTimer); });
window.addEventListener('pageshow', event => { if (event.persisted) location.reload(); });
api('/portal/me').then(data => enter(data.user)).catch(async error => { await showLogin(); if (!error.message.includes('Inicia sesion')) $('login-error').textContent = error.message; });
