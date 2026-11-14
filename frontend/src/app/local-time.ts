/** Format an instant in the browser's local timezone to minute precision. */
export function formatLocalTime(value: string | Date): string {
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) return '';
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${String(date.getFullYear()).padStart(4, '0')}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}:${pad(date.getHours())}${pad(date.getMinutes())}`;
}

/** Reject invalid calendar dates and local times skipped by daylight saving transitions. */
export function parseLocalTime(value: string): Date | null {
  const match = /^(\d{4})-(\d{2})-(\d{2}):(\d{2})(\d{2})$/.exec(value);
  if (!match) return null;
  const [, y, m, d, h, minute] = match.map(Number);
  if (y < 1) return null;
  const date = new Date(0);
  date.setFullYear(y, m - 1, d);
  date.setHours(h, minute, 0, 0);
  return date.getFullYear() === y && date.getMonth() === m - 1 && date.getDate() === d &&
    date.getHours() === h && date.getMinutes() === minute ? date : null;
}

/** Translate between the console format and the browser's native picker format. */
export function toPickerTime(value: string): string {
  return parseLocalTime(value) ? `${value.slice(0, 10)}T${value.slice(11, 13)}:${value.slice(13, 15)}` : '';
}

export function fromPickerTime(value: string): string {
  const match = /^(\d{4}-\d{2}-\d{2})T(\d{2}):(\d{2})$/.exec(value);
  return match ? `${match[1]}:${match[2]}${match[3]}` : '';
}
