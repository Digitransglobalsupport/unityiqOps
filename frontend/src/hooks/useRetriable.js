import { useCallback, useEffect, useRef, useState } from "react";

// Exponential backoff with jitter: 1,2,4,8,16,30 (max)
function nextDelay(attempt) {
  const base = Math.min(30, Math.pow(2, attempt - 1));
  const jitter = base * 0.2 * (Math.random() - 0.5) * 2; // +/-20%
  return Math.max(1, Math.min(30, Math.round(base + jitter)));
}

// classify error for retry eligibility
function isRetryable(error) {
  const status = error?.response?.status;
  if (!status) return true; // network or unknown error
  if (status >= 500 && status < 600) return true;
  return false; // do not retry 4xx
}

// Hook signature: useRetriable(fetchFn: ()=>Promise<any>, opts)
// opts: { key, maxAttempts=6, onSuccess, onFail }
export default function useRetriable(fetchFn, opts = {}) {
  const { key = "default", maxAttempts = 6, onSuccess, onFail } = opts;
  const [status, setStatus] = useState("idle"); // idle|retrying|failed|ok
  const [attempt, setAttempt] = useState(0);
  const [nextRetrySec, setNextRetrySec] = useState(0);
  const [suppressed, setSuppressed] = useState(false);
  const timerRef = useRef(null);
  const countdownRef = useRef(null);
  const pendingRef = useRef(false);

  const clearTimers = () => {
    if (timerRef.current) { clearTimeout(timerRef.current); timerRef.current = null; }
    if (countdownRef.current) { clearInterval(countdownRef.current); countdownRef.current = null; }
  };

  const doFetch = useCallback(async () => {
    if (pendingRef.current) return;
    pendingRef.current = true;
    try {
      const result = await fetchFn();
      clearTimers();
      setStatus("ok");
      setAttempt(0);
      setNextRetrySec(0);
      pendingRef.current = false;
      setSuppressed(false);
      onSuccess && onSuccess(result);
    } catch (e) {
      pendingRef.current = false;
      if (!isRetryable(e)) {
        clearTimers();
        setStatus("failed");
        onFail && onFail(e);
        return;
      }
      const nextAttempt = attempt + 1;
      if (nextAttempt > maxAttempts) {
        setStatus("failed");
        onFail && onFail(e);
        return;
      }
      setStatus("retrying");
      setAttempt(nextAttempt);
      const delay = nextDelay(nextAttempt);
      setNextRetrySec(delay);
      // countdown UI
      let remaining = delay;
      clearInterval(countdownRef.current);
      countdownRef.current = setInterval(() => {
        remaining -= 1;
        setNextRetrySec(remaining);
        if (remaining <= 0) { clearInterval(countdownRef.current); countdownRef.current = null; }
      }, 1000);
      // schedule retry
      clearTimeout(timerRef.current);
      timerRef.current = setTimeout(() => {
        doFetch();
      }, delay * 1000);
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [attempt, fetchFn, maxAttempts, onSuccess, onFail]);

  const start = useCallback(() => {
    setStatus("idle");
    setAttempt(0);
    setNextRetrySec(0);
    setSuppressed(false);
    doFetch();
  }, [doFetch]);

  const retryNow = useCallback(() => {
    clearTimers();
    setNextRetrySec(0);
    doFetch();
  }, [doFetch]);

  const dismiss = useCallback(() => {
    setSuppressed(true);
  }, []);

  useEffect(() => {
    return () => clearTimers();
  }, []);

  return {
    key,
    status, // idle|retrying|failed|ok
    attempt,
    nextRetrySec,
    retryNow,
    dismiss,
    suppressed,
    start,
  };
}
