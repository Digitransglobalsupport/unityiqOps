import formatRelativeTime, { lastSyncClass } from "../formatRelativeTime";

describe("formatRelativeTime", () => {
  test("returns em dash for falsy", () => {
    expect(formatRelativeTime(null)).toBe("—");
  });
  test("seconds/minutes/hours/days", () => {
    const now = Date.now();
    expect(formatRelativeTime(new Date(now - 15 * 1000).toISOString())).toBe("15s ago");
    expect(formatRelativeTime(new Date(now - 3 * 60 * 1000).toISOString())).toBe("3m ago");
    expect(formatRelativeTime(new Date(now - 2 * 3600 * 1000).toISOString())).toBe("2h ago");
    expect(formatRelativeTime(new Date(now - 25 * 3600 * 1000).toISOString())).toBe("yesterday");
    expect(formatRelativeTime(new Date(now - 5 * 24 * 3600 * 1000).toISOString())).toBe("5d ago");
  });
});

describe("lastSyncClass", () => {
  test("neutral <24h", () => {
    const iso = new Date(Date.now() - 2 * 3600 * 1000).toISOString();
    expect(lastSyncClass(iso)).toMatch("gray-100");
  });
  test("warn 24-72h", () => {
    const iso = new Date(Date.now() - 36 * 3600 * 1000).toISOString();
    expect(lastSyncClass(iso)).toMatch("yellow-100");
  });
  test("error >72h", () => {
    const iso = new Date(Date.now() - 100 * 3600 * 1000).toISOString();
    expect(lastSyncClass(iso)).toMatch("red-100");
  });
  test("unknown", () => {
    expect(lastSyncClass(null)).toMatch("gray-100");
  });
});
