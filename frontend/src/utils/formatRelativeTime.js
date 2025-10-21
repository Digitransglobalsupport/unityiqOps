export default function formatRelativeTime(iso) {
  if (!iso) return "—";
  try {
    const t = new Date(iso).getTime();
    if (isNaN(t)) return "—";
    const diffMs = Date.now() - t;
    const sec = Math.floor(diffMs / 1000);
    if (sec < 60) return `${sec}s ago`;
    const min = Math.floor(sec / 60);
    if (min < 60) return `${min}m ago`;
    const hr = Math.floor(min / 60);
    if (hr < 24) return `${hr}h ago`;
    const day = Math.floor(hr / 24);
    if (day === 1) return "yesterday";
    return `${day}d ago`;
  } catch {
    return "—";
  }
}

export function lastSyncClass(iso) {
  if (!iso) return "text-xs px-2 py-1 rounded bg-gray-100 text-gray-700";
  try {
    const t = new Date(iso).getTime();
    const hr = (Date.now() - t) / 3600000;
    if (hr > 72) return "text-xs px-2 py-1 rounded bg-red-100 text-red-700";
    if (hr > 24) return "text-xs px-2 py-1 rounded bg-yellow-100 text-yellow-800";
    return "text-xs px-2 py-1 rounded bg-gray-100 text-gray-700";
  } catch {
    return "text-xs px-2 py-1 rounded bg-gray-100 text-gray-700";
  }
}
