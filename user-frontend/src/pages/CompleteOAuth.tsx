import React, { useEffect, useMemo, useState } from 'react';
import { post } from '../services/api';
import { useAuth } from '../context/AuthContext';
import { useToast } from '../components/common/Toast';
import { extractErrorMessage } from '../utils/errors';
import Input from '../components/ui/Input';
import Button from '../components/ui/Button';

type AuthResponse = {
  token: string;
  expiresAt: number;
  user: { id: number; username: string; email: string; role: string };
};

const CompleteOAuthPage: React.FC = () => {
  const { refresh } = useAuth();
  const search = useMemo(() => new URLSearchParams(window.location.search), []);

  const [email, setEmail] = useState<string>('');
  const [regToken, setRegToken] = useState<string>('');
  const [username, setUsername] = useState<string>('');
  const [firstName, setFirstName] = useState<string>('');
  const [lastName, setLastName] = useState<string>('');
  const [password, setPassword] = useState<string>('');
  const [confirmPassword, setConfirmPassword] = useState<string>('');
  const [passwordError, setPasswordError] = useState<string | undefined>(undefined);
  const [confirmError, setConfirmError] = useState<string | undefined>(undefined);
  const [termsAccepted, setTermsAccepted] = useState<boolean>(false);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const { toast } = useToast();

  useEffect(() => {
    const qEmail = search.get('email') || '';
    const qToken = search.get('regToken') || '';
    const preU = search.get('preUsername') || '';
    setEmail(qEmail);
    setRegToken(qToken);
    const base = preU || (qEmail.includes('@') ? qEmail.split('@')[0] : '');
    setUsername(base);
    // Do not autofill first/last name; leave blank for user input
    setFirstName('');
    setLastName('');
  }, [search]);

  const onSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (loading) return;
    setError(null);
    if (!regToken) {
      setError('Missing registration token. Please re-start Google sign in.');
      return;
    }
    if (!termsAccepted) {
      setError('Please accept the Terms of Service.');
      return;
    }
    // Validate password per policy and confirmation
    const weak = !password || password.length < 8 || !/[a-z]/.test(password) || !/[A-Z]/.test(password) || !/[0-9]/.test(password) || !/[^A-Za-z0-9]/.test(password);
    if (weak) {
      const msg = 'Use 8+ chars with upper, lower, number, symbol.';
      setPasswordError(msg);
      setError(msg);
      return;
    }
    if (password !== confirmPassword) {
      const msg = 'Passwords do not match';
      setConfirmError(msg);
      setError(msg);
      return;
    }
    setLoading(true);
    try {
      const res = await post<{ status: string; message: string; data: AuthResponse }>(
        '/auth/register-oauth',
        {
          regToken,
          username,
          password,
          termsAccepted,
          // firstName/lastName are currently not used by backend for this endpoint but kept for UI completeness
          firstName,
          lastName,
        }
      );
      const data = res.data.data;
      if (data?.token) {
        localStorage.setItem('auth_token', data.token);
        await refresh();
        toast('Registration successful', 'success');
        window.location.href = '/';
      } else {
        const msg = 'Registration completed, but no token returned. Please login.';
        setError(msg);
        toast(msg, 'error');
      }
    } catch (err: any) {
      const msg = extractErrorMessage(err, 'Registration failed');
      setError(msg);
      toast(msg, 'error');
    } finally {
      setLoading(false);
    }
  };

  // Live validation on typing
  useEffect(() => {
    const weak = !password || password.length < 8 || !/[a-z]/.test(password) || !/[A-Z]/.test(password) || !/[0-9]/.test(password) || !/[^A-Za-z0-9]/.test(password);
    setPasswordError(weak ? 'Use 8+ chars with upper, lower, number, symbol.' : undefined);
  }, [password]);

  useEffect(() => {
    if (!confirmPassword) { setConfirmError(undefined); return; }
    setConfirmError(password !== confirmPassword ? 'Passwords do not match' : undefined);
  }, [password, confirmPassword]);

  return (
    <div className="min-h-screen bg-gray-50 flex items-center justify-center px-4">
      <div className="w-full max-w-md">
        <div className="bg-white shadow rounded-lg p-6">
          <h1 className="text-xl font-semibold mb-4 text-gray-900">Complete your account</h1>
          {error && (
            <div className="mb-4 rounded-md bg-red-50 text-red-700 px-3 py-2 text-sm">{error}</div>
          )}
          <form onSubmit={onSubmit} className="space-y-4">
            <Input id="email" label="Email" value={email} disabled className="bg-gray-100 text-gray-600" />
            <Input id="username" label="Username" value={username} onChange={(e) => setUsername(e.target.value)} placeholder="yourname" required />
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <Input id="firstName" label="First name" value={firstName} onChange={(e) => setFirstName(e.target.value)} placeholder="Ada" />
              <Input id="lastName" label="Last name" value={lastName} onChange={(e) => setLastName(e.target.value)} placeholder="Lovelace" />
            </div>
            <Input id="password" label="Password" type="password" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="Set a password" error={passwordError} withToggle required />
            <Input id="confirmPassword" label="Confirm password" type="password" value={confirmPassword} onChange={(e) => setConfirmPassword(e.target.value)} placeholder="Confirm password" error={confirmError} withToggle required />
            <p className="text-xs text-gray-500">Use at least 8 characters with uppercase, lowercase, number, and symbol.</p>
            <input type="hidden" name="regToken" value={regToken} />
            <div className="flex items-center">
              <input id="terms" type="checkbox" checked={termsAccepted} onChange={(e) => setTermsAccepted(e.target.checked)} className="h-4 w-4 rounded border-gray-300 text-blue-600 focus:ring-blue-500" required />
              <label htmlFor="terms" className="ml-2 text-sm text-gray-700">I accept the Terms of Service</label>
            </div>
            <Button type="submit" full disabled={loading}>{loading ? 'Creating account...' : 'Create account'}</Button>
          </form>
        </div>
      </div>
    </div>
  );
};

export default CompleteOAuthPage;


