import React, { useEffect, useMemo, useState } from 'react';
import { post } from '../services/api';
import ErrorAlert from '../components/common/ErrorAlert';
import { useToast } from '../components/common/Toast';
import { extractErrorMessage } from '../utils/errors';
import Input from '../components/ui/Input';

const ResetPasswordPage: React.FC = () => {
  const qs = useMemo(() => new URLSearchParams(window.location.search), []);
  const [token, setToken] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [passwordError, setPasswordError] = useState<string | undefined>(undefined);
  const [confirmError, setConfirmError] = useState<string | undefined>(undefined);
  const [done, setDone] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const { toast } = useToast();

  useEffect(() => {
    setToken(qs.get('token') || '');
  }, [qs]);

  // Live validation on typing
  useEffect(() => {
    const weak = !password || password.length < 8 || !/[a-z]/.test(password) || !/[A-Z]/.test(password) || !/[0-9]/.test(password) || !/[^A-Za-z0-9]/.test(password);
    setPasswordError(weak ? 'Use 8+ chars with upper, lower, number, symbol.' : undefined);
  }, [password]);

  useEffect(() => {
    if (!confirmPassword) { setConfirmError(undefined); return; }
    setConfirmError(password !== confirmPassword ? 'Passwords do not match' : undefined);
  }, [password, confirmPassword]);

  const onSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (loading) return;
    setError(null);

    if (passwordError) { setError(passwordError); return; }
    if (confirmError) { setError(confirmError); return; }

    setLoading(true);
    try {
      await post('/auth/reset-password', { token, password });
      setDone(true);
      toast('Password reset successful', 'success');
    } catch (err: any) {
      const msg = extractErrorMessage(err, 'Failed to reset password');
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
          <h1 className="text-xl font-semibold mb-4 text-gray-900">Reset Password</h1>
          {done ? (
            <div className="space-y-3">
              <div className="rounded-md bg-green-50 text-green-800 px-3 py-2 text-sm">Password reset successful</div>
              <a href="/login" className="inline-block rounded-md bg-blue-600 px-3 py-2 text-white text-sm font-medium hover:bg-blue-700">Go to Login</a>
            </div>
          ) : (
            <form onSubmit={onSubmit} className="space-y-4">
              {error && <ErrorAlert message={error} />}
              <Input id="password" label="New password" type="password" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="••••••••" error={passwordError} withToggle required />
              <Input id="confirmPassword" label="Confirm password" type="password" value={confirmPassword} onChange={(e) => setConfirmPassword(e.target.value)} placeholder="••••••••" error={confirmError} withToggle required />
              <p className="text-xs text-gray-500 mt-1">Use at least 8 characters with uppercase, lowercase, number, and symbol.</p>
              <button
                type="submit"
                disabled={loading}
                className="w-full rounded-md bg-blue-600 px-3 py-2 text-white text-sm font-medium hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:opacity-60"
              >
                {loading ? 'Resetting...' : 'Reset password'}
              </button>
            </form>
          )}
        </div>
      </div>
    </div>
  );
};

export default ResetPasswordPage;


