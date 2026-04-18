import { createContext, useCallback, useContext, useRef, useState } from "react";

const ToastContext = createContext(null);

const MAX_VISIBLE = 3;
const AUTO_DISMISS_MS = 4000;

let _idCounter = 0;

export function ToastProvider({ children }) {
  const [toasts, setToasts] = useState([]);
  const timers = useRef({});

  const dismiss = useCallback((id) => {
    clearTimeout(timers.current[id]);
    delete timers.current[id];
    setToasts((prev) =>
      prev.map((t) => (t.id === id ? { ...t, exiting: true } : t))
    );
    setTimeout(() => {
      setToasts((prev) => prev.filter((t) => t.id !== id));
    }, 200);
  }, []);

  const showToast = useCallback(
    (message, type = "info") => {
      const id = ++_idCounter;
      setToasts((prev) => {
        const next = [...prev, { id, message, type, exiting: false }];
        /* Evict oldest if over max */
        while (next.filter((t) => !t.exiting).length > MAX_VISIBLE) {
          const oldest = next.find((t) => !t.exiting);
          if (oldest) oldest.exiting = true;
          else break;
        }
        return next;
      });

      timers.current[id] = setTimeout(() => dismiss(id), AUTO_DISMISS_MS);

      return id;
    },
    [dismiss]
  );

  return (
    <ToastContext.Provider value={{ toasts, showToast, dismiss }}>
      {children}
    </ToastContext.Provider>
  );
}

export default function useToast() {
  const ctx = useContext(ToastContext);
  if (!ctx) {
    throw new Error("useToast must be used within a <ToastProvider>");
  }
  return ctx;
}
