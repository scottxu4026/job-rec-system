import React, { useEffect } from 'react';
import { useAuth } from '../context/AuthContext';

const HomePage: React.FC = () => {
  const { refresh } = useAuth();
  // Capture token from OAuth2 redirect fragment (#token=...&expiresAt=...)
  useEffect(() => {
    const hash = window.location.hash;
    if (hash && hash.includes('token=')) {
      const params = new URLSearchParams(hash.replace(/^#/, ''));
      const t = params.get('token');
      if (t) {
        localStorage.setItem('auth_token', t);
        // Clean URL fragment
        history.replaceState(null, '', window.location.pathname);
        refresh().catch(() => {});
      }
    }
  }, [refresh]);
  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-semibold text-gray-900">User Service Demo</h1>
      <p className="text-sm text-gray-700">Explore common authentication flows:</p>
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <aside className="md:col-span-1 bg-white rounded-md border border-gray-200 p-4">
          <h2 className="font-medium text-gray-900 mb-3">Filters</h2>
          <div className="space-y-2 text-sm text-gray-700">
            <div>Keywords</div>
            <div>Location</div>
            <div>Salary</div>
            <div>Type</div>
          </div>
        </aside>
        <section className="md:col-span-2 space-y-3">
          {[1,2,3,4,5].map((i) => (
            <div key={i} className="bg-white rounded-md border border-gray-200 p-4 hover:shadow">
              <div className="flex justify-between">
                <h3 className="font-semibold text-gray-900">Job Title {i}</h3>
                <span className="text-xs text-gray-500">San Francisco, CA</span>
              </div>
              <p className="text-sm text-gray-700 mt-1">Company name • $100k–$150k • Remote friendly</p>
              <p className="text-sm text-gray-600 mt-2">Short description of the role and responsibilities.</p>
              <div className="mt-2 text-xs text-gray-500">Posted 2 days ago</div>
            </div>
          ))}
        </section>
        <aside className="md:col-span-1 bg-white rounded-md border border-gray-200 p-4">
          <h2 className="font-medium text-gray-900 mb-3">Job details</h2>
          <p className="text-sm text-gray-700">Select a job to view full details here, including description, requirements, and how to apply.</p>
        </aside>
      </div>
    </div>
  );
};

export default HomePage;


