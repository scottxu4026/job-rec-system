import React from 'react';
import RegisterForm from '../components/auth/RegisterForm';
import Card from '../components/ui/Card';
import Button from '../components/ui/Button';

const RegisterPage: React.FC = () => {
  return (
    <div className="min-h-screen bg-gray-50 flex items-center justify-center px-4">
      <div className="w-full max-w-md">
        <Card title="Create your account" footer={
          <Button
            variant="secondary"
            full
            onClick={() => {
              const base = (import.meta as any).env?.VITE_API_BASE_URL || '/api';
              window.location.href = `${base}/oauth2/authorization/google`;
            }}
          >
            Continue with Google
          </Button>
        }>
          <RegisterForm />
          <div className="mt-4 text-sm text-gray-600">
            Already have an account? <a className="hover:underline" href="/login">Sign in</a>
          </div>
        </Card>
      </div>
    </div>
  );
};

export default RegisterPage;


