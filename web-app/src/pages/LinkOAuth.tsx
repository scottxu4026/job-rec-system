import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { post } from '../services/api';
import { useAuth } from '../context/AuthContext';
import { useToast } from '../components/common/Toast';
import { extractErrorMessage } from '../utils/errors';
import Button from '../components/ui/Button';

type AuthResponse = {
  token: string;
  expiresAt: number;
  user: { id: number; username: string; email: string; role: string };
};

const LinkOAuthPage: React.FC = () => {
  const { refresh } = useAuth();
  const qs = useMemo(() => new URLSearchParams(window.location.search), []);
  const [linkToken, setLinkToken] = useState<string>('');
  const [status, setStatus] = useState<'idle' | 'linking' | 'success' | 'error'>('idle');
  const [message, setMessage] = useState<string>('');
  const { toast } = useToast();

  useEffect(() => {
    const token = qs.get('linkToken') || '';
    setLinkToken(token);
    if (!token) {
      setStatus('error');
      setMessage('Missing link token.');
    }
  }, [qs]);

  const onLink = useCallback(async () => {
    if (!linkToken) return;
    setStatus('linking');
    setMessage('Linking your account...');
    try {
      const res = await post<{ status: string; message: string; data: AuthResponse }>(
        '/auth/link-oauth',
        { linkToken }
      );
      const data = res.data.data;
      if (data?.token) {
        localStorage.setItem('auth_token', data.token);
        setStatus('success');
        setMessage('Linked successfully. Redirecting...');
        await refresh();
        toast('Linked successfully', 'success');
        window.location.href = '/';
      } else {
        setStatus('error');
        const msg = 'Linking completed but no token returned. Please login.';
        setMessage(msg);
        toast(msg, 'error');
      }
    } catch (err: any) {
      const msg = extractErrorMessage(err, 'Failed to link account');
      setStatus('error');
      setMessage(msg);
      toast(msg, 'error');
    }
  }, [linkToken, refresh]);

  return (
    <div className="min-h-screen bg-gray-50 flex items-center justify-center px-4">
      <div className="w-full max-w-md">
        <div className="bg-white shadow rounded-lg p-6 text-center">
          <h1 className="text-xl font-semibold text-gray-900">Link Google to your account</h1>
          <p className="mt-2 text-sm text-gray-700">Enable Google as a sign in method for your existing account.</p>

          {status === 'error' && (
            <div className="mt-4 rounded-md bg-red-50 text-red-700 px-3 py-2 text-sm">{message}</div>
          )}
          {status === 'success' && (
            <div className="mt-4 rounded-md bg-green-50 text-green-800 px-3 py-2 text-sm">{message}</div>
          )}
          {status === 'linking' && (
            <div className="mt-4 flex flex-col items-center">
              <div className="h-10 w-10 border-4 border-blue-200 border-t-blue-600 rounded-full animate-spin" />
              <p className="mt-2 text-sm text-gray-700">{message}</p>
            </div>
          )}

          <div className="mt-6">
            <Button onClick={onLink} disabled={!linkToken || status === 'linking'} full>
              Link my account
            </Button>
          </div>
          <div className="mt-3">
            <a href="/login" className="text-sm text-blue-600 hover:underline">Return to login</a>
          </div>
        </div>
      </div>
    </div>
  );
};

export default LinkOAuthPage;


