import React from 'react';

type Props = React.ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: 'primary' | 'secondary' | 'ghost' | 'danger';
  full?: boolean;
};

const variants: Record<NonNullable<Props['variant']>, string> = {
  primary: 'bg-blue-600 text-white hover:bg-blue-700 focus:ring-blue-500',
  secondary: 'bg-gray-100 text-gray-800 hover:bg-gray-200 focus:ring-gray-400',
  ghost: 'bg-transparent text-gray-700 hover:bg-gray-100 focus:ring-gray-400',
  danger: 'bg-red-600 text-white hover:bg-red-700 focus:ring-red-500',
};

const Button: React.FC<Props> = ({ variant = 'primary', full, className = '', ...props }) => {
  const base = 'rounded-md px-3 py-2 text-sm font-medium focus:outline-none focus:ring-2 disabled:opacity-60';
  const width = full ? 'w-full' : '';
  return <button className={`${base} ${variants[variant]} ${width} ${className}`} {...props} />;
};

export default Button;


