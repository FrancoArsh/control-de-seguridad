export function csvCell(value) {
  let text = String(value ?? '');
  if (/^[\s\u0000-\u001f]*[=+@-]/.test(text)) text = "'" + text;
  return '"' + text.replace(/"/g, '""') + '"';
}

export function historyCsv(rows) {
  const header = ['Fecha y hora', 'Persona', 'Identificador', 'Sede', 'Tipo', 'Movimiento', 'Resultado', 'Motivo', 'Validador'];
  const data = rows.map(row => [
    Number.isFinite(row.timestamp) && row.timestamp > 0 ? new Date(row.timestamp).toISOString() : '',
    row.name, row.id, row.sede, row.tipoUsuario, row.accessType,
    row.authorized ? 'Autorizado' : 'Rechazado', row.reason, row.validatedBy
  ]);
  return '\ufeff' + [header, ...data].map(row => row.map(csvCell).join(',')).join('\r\n');
}
