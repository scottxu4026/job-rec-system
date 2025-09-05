import React from 'react';
import LoginForm from '../components/auth/LoginForm';
import Card from '../components/ui/Card';
import Button from '../components/ui/Button';

const LoginPage: React.FC = () => {
  const onGoogle = () => {
    const base = (import.meta as any).env?.VITE_API_BASE_URL || '/api';
    window.location.href = `${base}/oauth2/authorization/google`;
  };

  return (
    <div className="min-h-screen bg-gray-50 flex items-center justify-center px-4">
      <div className="w-full max-w-md">
        <Card title="Sign in to your account" footer={
          <Button variant="secondary" full onClick={onGoogle}>Continue with Google</Button>
        }>
          <LoginForm />
          <div className="mt-4 text-sm text-gray-600">
            <a className="hover:underline" href="/forgot-password">Forgot your password?</a>
            <span className="mx-2">•</span>
            <a className="hover:underline" href="/register">Create account</a>
          </div>
        </Card>
      </div>
    </div>
  );
};

export default LoginPage;


