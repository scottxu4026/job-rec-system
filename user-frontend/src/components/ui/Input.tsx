import React, { useState, useMemo } from 'react';

type Props = React.InputHTMLAttributes<HTMLInputElement> & {
  error?: string;
  label?: string;
  hint?: string;
  withToggle?: boolean; // show eye button for password visibility
};

const Input: React.FC<Props> = ({ id, label, error, hint, className = '', withToggle = false, type, ...props }) => {
  const [visible, setVisible] = useState(false);
  const computedType = useMemo(() => {
    if (!withToggle) return type;
    return visible ? 'text' : (type || 'password');
  }, [withToggle, visible, type]);
  return (
    <div>
      {label && (
        <label htmlFor={id} className="block text-sm font-medium mb-1 text-gray-700">{label}</label>
      )}
      <div className="relative">
        <input
          id={id}
          className={`w-full rounded-md border px-3 py-2 text-sm focus:outline-none focus:ring-2 ${error ? 'border-red-300 focus:ring-red-400' : 'border-gray-300 focus:ring-blue-500'} bg-white text-gray-900 ${withToggle ? 'pr-10' : ''} ${className}`}
          type={computedType}
          {...props}
        />
        {withToggle && (
          <button
            type="button"
            onClick={() => setVisible((v) => !v)}
            aria-label={visible ? 'Hide password' : 'Show password'}
            className="absolute inset-y-0 right-2 flex items-center text-gray-500 hover:text-gray-700 bg-transparent border-0 p-0 focus:outline-none focus:ring-0"
          >
            {visible ? (
              // Eye-off icon
              <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="h-5 w-5">
                <path d="M3 3l18 18" strokeLinecap="round" strokeLinejoin="round"/>
                <path d="M10.584 10.587A2 2 0 0012 14a2 2 0 001.414-3.414M7.05 7.05C5.186 8.203 3.75 9.91 3 12c1.5 4 5.5 7 9 7 1.223 0 2.395-.28 3.465-.79M13.73 6.27A9.43 9.43 0 0012 5c-3.5 0-7.5 3-9 7 .44 1.173 1.114 2.24 1.97 3.16" strokeLinecap="round" strokeLinejoin="round"/>
              </svg>
            ) : (
              // Eye icon
              <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="h-5 w-5">
                <path d="M1 12s4-7 11-7 11 7 11 7-4 7-11 7-11-7-11-7z" strokeLinecap="round" strokeLinejoin="round"/>
                <circle cx="12" cy="12" r="3" />
              </svg>
            )}
          </button>
        )}
      </div>
      {error && <p className="mt-1 text-xs text-red-600">{error}</p>}
      {!error && hint && <p className="mt-1 text-xs text-gray-500">{hint}</p>}
    </div>
  );
};

export default Input;


