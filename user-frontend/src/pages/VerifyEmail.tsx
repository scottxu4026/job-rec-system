import React, { useEffect, useState } from 'react';
import { get } from '../services/api';
import { useAuth } from '../context/AuthContext';
import { useToast } from '../components/common/Toast';
import { extractErrorMessage } from '../utils/errors';

type AuthResponse = {
  token: string;
  expiresAt: number;
  user: { id: number; username: string; email: string; role: string };
};

const VerifyEmailPage: React.FC = () => {
  const { refresh } = useAuth();
  const { toast } = useToast();
  const [status, setStatus] = useState<'idle' | 'loading' | 'success' | 'error'>('idle');
  const [message, setMessage] = useState<string>('');
  const [autoLogin, setAutoLogin] = useState<boolean>(true);

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const token = params.get('token');
    const autoLoginParam = params.get('autoLogin');
    const shouldAuto = autoLoginParam === 'false' ? false : true;
    setAutoLogin(shouldAuto);

    if (!token) {
      setStatus('error');
      setMessage('Invalid verification link');
      return;
    }

    setStatus('loading');
    get<{ status: string; message: string; data?: AuthResponse }>(
      '/auth/verify',
      { params: { token, autoLogin: shouldAuto } }
    )
      .then((res) => {
        const data = res.data?.data as AuthResponse | undefined;
        if (shouldAuto && data?.token) {
          localStorage.setItem('auth_token', data.token);
          setStatus('success');
          setMessage('Email verified. Redirecting...');
          // Refresh user and redirect home
          refresh().finally(() => {
            toast('Email verified', 'success');
            window.location.href = '/';
          });
        } else {
          // Auto-redirect to login when not autoLogin
          toast('Email verified', 'success');
          window.location.href = '/login';
        }
      })
      .catch((err) => {
        const msg = extractErrorMessage(err, 'Verification failed');
        setStatus('error');
        setMessage(msg);
        toast(msg, 'error');
      });
  }, [refresh]);

  return (
    <div className="min-h-screen bg-gray-50 flex items-center justify-center px-4">
      <div className="w-full max-w-md">
        <div className="bg-white shadow rounded-lg p-6 text-center">
          {status === 'loading' && (
            <>
              <div className="mx-auto h-10 w-10 border-4 border-blue-200 border-t-blue-600 rounded-full animate-spin" />
              <p className="mt-4 text-sm text-gray-700">Verifying your email...</p>
            </>
          )}

          {status === 'success' && (
            <>
              <h1 className="text-lg font-semibold text-gray-900">Success</h1>
              <p className="mt-2 text-sm text-gray-700">{message}</p>
              {!autoLogin && (
                <a href="/login" className="mt-4 inline-block rounded-md bg-blue-600 px-3 py-2 text-white text-sm font-medium hover:bg-blue-700">
                  Go to Login
                </a>
              )}
            </>
          )}

          {status === 'error' && (
            <>
              <h1 className="text-lg font-semibold text-red-700">Verification failed</h1>
              <p className="mt-2 text-sm text-red-600">{message}</p>
              <a href="/login" className="mt-4 inline-block rounded-md border border-gray-300 bg-white px-3 py-2 text-sm font-medium text-gray-700 hover:bg-gray-100">
                Return to Login
              </a>
            </>
          )}
        </div>
      </div>
    </div>
  );
};

export default VerifyEmailPage;


