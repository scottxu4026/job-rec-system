import React from 'react';

const ErrorAlert: React.FC<{ message?: string }> = ({ message }) => {
  if (!message) return null;
  return (
    <div className="rounded-md bg-red-50 text-red-700 px-3 py-2 text-sm">
      {message}
    </div>
  );
};

export default ErrorAlert;


