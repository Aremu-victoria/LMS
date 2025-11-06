"use client";
import { createContext, useCallback, useContext, useMemo, useState } from 'react';

type Toast = { id: number; message: string; type?: 'success' | 'error' | 'info' };

const ToastContext = createContext<{ showToast: (message: string, type?: Toast['type']) => void } | null>(null);

export function useToast() {
  const ctx = useContext(ToastContext);
  if (!ctx) throw new Error('useToast must be used within ToastProvider');
  return ctx;
}

export default function ToastProvider({ children }: { children: React.ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const showToast = useCallback((message: string, type?: Toast['type']) => {
    const id = Date.now() + Math.random();
    setToasts((prev) => [...prev, { id, message, type }]);
    setTimeout(() => setToasts((prev) => prev.filter((t) => t.id !== id)), 3500);
  }, []);

  const value = useMemo(() => ({ showToast }), [showToast]);

  return (
    <ToastContext.Provider value={value}>
      {children}
      <div className="fixed top-4 right-4 z-50 space-y-2">
        {toasts.map((t) => (
          <div
            key={t.id}
            className={
              `rounded-md px-4 py-2 shadow text-sm ` +
              (t.type === 'success' ? 'bg-emerald-50 text-emerald-800 border border-emerald-200' :
               t.type === 'error' ? 'bg-rose-50 text-rose-800 border border-rose-200' :
               'bg-slate-50 text-slate-800 border border-slate-200')
            }
          >
            {t.message}
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}



