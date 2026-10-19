import test from 'node:test';
import assert from 'node:assert/strict';
import { summarizeGuards } from '../../dist/guard-summary.js';

test('guard counts include people without shifts and distinguish disabled accounts', () => {
  assert.deepEqual(summarizeGuards({ a: { active: true }, b: { active: false }, legacy: { name: 'Legacy' }, invalid: null }),
    { total: 3, active: 2, inactive: 1 });
  assert.deepEqual(summarizeGuards(null), { total: 0, active: 0, inactive: 0 });
});
