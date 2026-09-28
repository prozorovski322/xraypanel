import { CheckCircle2, AlertTriangle, X } from "lucide-react";
import { createContext, useCallback, useContext, useMemo, useRef, useState, type ReactNode } from "react";

import { cn } from "@/lib/utils";

interface Toast {
  id: number;
  tone: "ok" | "bad";
  message: string;
}

interface ToastContextValue {
  ok(message: string): void;
  error(error: unknown): void;
}

const ToastContext = createContext<ToastContextValue | null>(null);

/**
 * A minimal toaster: every mutation reports its outcome, and a failure says what the panel
 * said rather than "something went wrong". Announced through a live region so a screen
 * reader hears it too.
 */
export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const next = useRef(1);

  const dismiss = useCallback((id: number) => {
    setToasts((current) => current.filter((toast) => toast.id !== id));
  }, []);

  const push = useCallback(
    (tone: Toast["tone"], message: string) => {
      const id = next.current++;
      setToasts((current) => [...current.slice(-3), { id, tone, message }]);
      // Errors stay longer: they are the ones somebody needs to read.
      window.setTimeout(() => dismiss(id), tone === "bad" ? 8000 : 3500);
    },
    [dismiss],
  );

  const value = useMemo<ToastContextValue>(
    () => ({
      ok: (message) => push("ok", message),
      error: (error) => push("bad", error instanceof Error ? error.message : String(error)),
    }),
    [push],
  );

  return (
    <ToastContext.Provider value={value}>
      {children}
      <div className="pointer-events-none fixed right-4 bottom-4 z-50 flex w-80 flex-col gap-2" aria-live="polite">
        {toasts.map((toast) => (
          <div
            key={toast.id}
            role={toast.tone === "bad" ? "alert" : "status"}
            className={cn(
              "pointer-events-auto flex items-start gap-2 rounded-md border px-3 py-2 text-sm shadow-lg",
              toast.tone === "ok" ? "border-ok/30 bg-surface text-text" : "border-bad/30 bg-bad-soft text-bad",
            )}
          >
            {toast.tone === "ok" ? (
              <CheckCircle2 className="mt-0.5 size-4 shrink-0 text-ok" aria-hidden />
            ) : (
              <AlertTriangle className="mt-0.5 size-4 shrink-0" aria-hidden />
            )}
            <span className="flex-1">{toast.message}</span>
            <button className="text-muted hover:text-text" onClick={() => dismiss(toast.id)} aria-label="Dismiss">
              <X className="size-3.5" />
            </button>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}

export function useToast(): ToastContextValue {
  const value = useContext(ToastContext);
  if (!value) throw new Error("useToast must be used inside ToastProvider");
  return value;
}
