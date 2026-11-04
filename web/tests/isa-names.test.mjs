// Display names of the ISAs the raw-code model reports since the fw1 audit
// (2026-11-04): without an ISA_NAMES entry the UI shows the JSON ID.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { isaName } from '../format.js';

const MODEL_ISAS = {
  i8085: 'Intel 8080/8085',
  mn10300: 'MN10300',
  hc11: '68HC11',
  unsp: 'unSP',
  w65816: '65816',
};

test('raw-code model ISAs have display names', () => {
  for (const [id, name] of Object.entries(MODEL_ISAS)) {
    assert.equal(isaName(id), name, id);
  }
});
