import React, { useState } from 'react';
import { post } from '../services/api';
import ErrorAlert from '../components/common/ErrorAlert';
import { useToast } from '../components/common/Toast';
import { extractErrorMessage } from '../utils/errors';

const ForgotPasswordPage: React.FC = () => {
  const [email, setEmail] = useState('');
  const [sent, setSent] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const { toast } = useToast();

  const onSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (loading) return;
    setError(null);
    setLoading(true);
    try {
      await post('/auth/forgot-password', { email });
      setSent(true);
      toast('Reset email sent', 'success');
    } catch (err: any) {
      const msg = extractErrorMessage(err, 'Failed to send reset email');
      setError(msg);
      toast(msg, 'error');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gray-50 flex items-center justify-center px-4">
      <div className="w-full max-w-md">
        <div className="bg-white shadow rounded-lg p-6">
          <h1 className="text-xl font-semibold mb-4 text-gray-900">Forgot Password</h1>
          {sent ? (
            <div className="rounded-md bg-green-50 text-green-800 px-3 py-2 text-sm">Reset email sent</div>
          ) : (
            <form onSubmit={onSubmit} className="space-y-4">
              {error && <ErrorAlert message={error} />}
              <div>
                <label className="block text-sm font-medium mb-1" htmlFor="email">Email</label>
                <input
                  id="email"
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="w-full rounded-md border border-gray-300 bg-white px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                  placeholder="you@example.com"
                  required
                />
              </div>
              <button
                type="submit"
                disabled={loading}
                className="w-full rounded-md bg-blue-600 px-3 py-2 text-white text-sm font-medium hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:opacity-60"
              >
                {loading ? 'Sending...' : 'Send reset email'}
              </button>
            </form>
          )}
        </div>
      </div>
    </div>
  );
};

export default ForgotPasswordPage;


