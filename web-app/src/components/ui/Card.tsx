import React from 'react';

const Card: React.FC<{ title?: string; children: React.ReactNode; footer?: React.ReactNode }>
  = ({ title, children, footer }) => {
  return (
    <div className="bg-white shadow rounded-lg p-6">
      {title && <h1 className="text-xl font-semibold mb-4 text-gray-900">{title}</h1>}
      {children}
      {footer && <div className="mt-4">{footer}</div>}
    </div>
  );
};

export default Card;


