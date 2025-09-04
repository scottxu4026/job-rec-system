import React, { createContext, useCallback, useContext, useMemo, useState } from 'react';

type ToastItem = { id: number; message: string; type?: 'info' | 'success' | 'error' };
type ToastContextValue = { toast: (message: string, type?: ToastItem['type']) => void };

const ToastContext = createContext<ToastContextValue | undefined>(undefined);

export const ToastProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [items, setItems] = useState<ToastItem[]>([]);

  const toast = useCallback((message: string, type: ToastItem['type'] = 'info') => {
    const id = Date.now() + Math.random();
    setItems((prev) => [...prev, { id, message, type }]);
    setTimeout(() => {
      setItems((prev) => prev.filter((t) => t.id !== id));
    }, 3000);
  }, []);

  const value = useMemo(() => ({ toast }), [toast]);

  return (
    <ToastContext.Provider value={value}>
      {children}
      <div className="fixed top-4 right-4 space-y-2 z-50">
        {items.map((t) => (
          <div
            key={t.id}
            className={
              'rounded-md px-3 py-2 text-sm shadow ' +
              (t.type === 'error'
                ? 'bg-red-600 text-white'
                : t.type === 'success'
                ? 'bg-green-600 text-white'
                : 'bg-gray-800 text-white')
            }
          >
            {t.message}
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
};

export const useToast = () => {
  const ctx = useContext(ToastContext);
  if (!ctx) throw new Error('useToast must be used within ToastProvider');
  return ctx;
};


