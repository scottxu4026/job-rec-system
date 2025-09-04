import React, { useEffect, useState } from 'react';
import { useAuth } from '../../context/AuthContext';
import LoadingSpinner from './LoadingSpinner';

const RequireAuth: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { isAuthenticated, refresh } = useAuth();
  const [checking, setChecking] = useState(false);

  useEffect(() => {
    if (!isAuthenticated) {
      setChecking(true);
      refresh().finally(() => {
        setChecking(false);
        if (typeof window !== 'undefined' && !isAuthenticated) {
          window.location.href = '/login';
        }
      });
    }
  }, [isAuthenticated, refresh]);

  if (checking) return <LoadingSpinner />;
  if (!isAuthenticated) return null;
  return <>{children}</>;
};

export default RequireAuth;


