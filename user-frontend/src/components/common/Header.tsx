import React from 'react';
import { useAuth } from '../../context/AuthContext';

const Header: React.FC = () => {
  const { isAuthenticated } = useAuth();
  return (
    <header className="border-b bg-white">
      <div className="mx-auto max-w-5xl px-4 h-12 flex items-center justify-between">
        <a href="/" className="font-semibold text-gray-900">User Service</a>
        <nav className="space-x-4 text-sm">
          <a className="text-gray-700 hover:underline" href="/">Home</a>
          {!isAuthenticated && <a className="text-gray-700 hover:underline" href="/login">Login</a>}
          {!isAuthenticated && <a className="text-gray-700 hover:underline" href="/register">Register</a>}
          {isAuthenticated && <a className="text-gray-700 hover:underline" href="/me">Me</a>}
        </nav>
      </div>
    </header>
  );
};

export default Header;


