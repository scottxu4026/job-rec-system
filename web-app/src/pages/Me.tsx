import React, { useEffect } from 'react';
import { useAuth } from '../context/AuthContext';

const MePage: React.FC = () => {
  const { user, isAuthenticated, refresh, logout } = useAuth();

  useEffect(() => {
    if (!user) {
      refresh().catch(() => {});
    }
  }, [user, refresh]);

  if (!isAuthenticated) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center px-4">
        <div className="text-sm text-gray-700">Redirecting to login...</div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50 flex items-center justify-center px-4">
      <div className="w-full max-w-md">
        <div className="bg-white shadow rounded-lg p-6">
          <h1 className="text-xl font-semibold mb-4 text-gray-900">My Profile</h1>
          <dl className="divide-y divide-gray-200 text-sm text-gray-800">
            <div className="py-2 flex justify-between">
              <dt className="text-gray-500">ID</dt>
              <dd>{user?.id}</dd>
            </div>
            <div className="py-2 flex justify-between">
              <dt className="text-gray-500">Username</dt>
              <dd>{user?.username}</dd>
            </div>
            <div className="py-2 flex justify-between">
              <dt className="text-gray-500">Email</dt>
              <dd>{user?.email}</dd>
            </div>
            <div className="py-2 flex justify-between">
              <dt className="text-gray-500">Role</dt>
              <dd>{user?.role}</dd>
            </div>
          </dl>
          <button
            onClick={logout}
            className="mt-6 w-full rounded-md bg-red-600 px-3 py-2 text-white text-sm font-medium hover:bg-red-700 focus:outline-none focus:ring-2 focus:ring-red-500"
          >
            Logout
          </button>
        </div>
      </div>
    </div>
  );
};

export default MePage;


