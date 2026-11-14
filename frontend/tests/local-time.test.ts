import { strict as assert } from 'node:assert';
import { formatLocalTime, parseLocalTime } from '../src/app/local-time';

for (const text of ['2026-11-14:1805', '2024-02-29:0000', '0001-01-01:0000']) {
  const date = parseLocalTime(text); assert(date); assert.equal(formatLocalTime(date), text);
}
for (const text of ['0000-01-01:0000', '2026-02-29:1200', '2026-13-01:1200', '2026-01-01:2400', '2026-01-01:1260', '2026-1-01:1200', '2026-01-01 12:00']) assert.equal(parseLocalTime(text), null);
console.log('Local timestamps round trip in YYYY-MM-DD:HHmm and reject invalid calendar values.');
if (process.env.TZ === 'America/New_York') {
  assert.equal(parseLocalTime('2026-03-08:0230'), null);
  assert(parseLocalTime('2026-03-08:0330'));
}
