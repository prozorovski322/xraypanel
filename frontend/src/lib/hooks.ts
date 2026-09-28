import { useCallback, useEffect, useState } from "react";

/** useDebounced delays a value, so a search box does not fire a query per keystroke. */
export function useDebounced<T>(value: T, delay = 300): T {
  const [debounced, setDebounced] = useState(value);
  useEffect(() => {
    const timer = window.setTimeout(() => setDebounced(value), delay);
    return () => window.clearTimeout(timer);
  }, [value, delay]);
  return debounced;
}

/**
 * useCopy copies text and remembers which item was copied for a moment, so the button can say
 * "Copied" — the only feedback there is that the clipboard now holds a subscription link.
 */
export function useCopy(): [string | null, (key: string, text: string) => Promise<boolean>] {
  const [copied, setCopied] = useState<string | null>(null);

  const copy = useCallback(async (key: string, text: string) => {
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      // The Clipboard API needs a secure context. Behind plain HTTP on a LAN address it is
      // unavailable, and the older selection-based copy still works there.
      const area = document.createElement("textarea");
      area.value = text;
      area.setAttribute("readonly", "");
      area.style.position = "fixed";
      area.style.opacity = "0";
      document.body.appendChild(area);
      area.select();
      const ok = document.execCommand("copy");
      document.body.removeChild(area);
      if (!ok) return false;
    }
    setCopied(key);
    window.setTimeout(() => setCopied((current) => (current === key ? null : current)), 1800);
    return true;
  }, []);

  return [copied, copy];
}
