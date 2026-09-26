import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { csvCell, historyCsv } from '../../../frontend/js/report.mjs';

test('el portal no tiene identificadores HTML duplicados', () => {
  const html = fs.readFileSync(new URL('../../../frontend/portal.html', import.meta.url), 'utf8');
  const ids = [...html.matchAll(/\bid="([^"]+)"/g)].map(match => match[1]);
  assert.equal(ids.length, new Set(ids).size);
});
test('CSV escapa comillas y neutraliza formulas', () => {
  assert.equal(csvCell('a,"b"'), '"a,""b"""');
  for (const value of ['=1+1', '+SUM(A1)', '-1+1', '@SUM(A1)', '  =1', '\t=1']) {
    assert.ok(csvCell(value).startsWith('"\''));
  }
  assert.ok(historyCsv([{ timestamp: 1, name: 'Persona', authorized: false }]).includes('Rechazado'));
  assert.equal(historyCsv([]).split('\r\n').length, 1);
});
