import React, { useState } from 'react';
import { useAuth } from '../../context/AuthContext';
import { post } from '../../services/api';
import { useToast } from '../../components/common/Toast';
import { extractErrorMessage } from '../../utils/errors';
import Input from '../ui/Input';
import Button from '../ui/Button';

const LoginForm: React.FC = () => {
  const { login } = useAuth();
  const [identifier, setIdentifier] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const { toast } = useToast();

  const onSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (loading) return;
    setLoading(true);
    try {
      await login(identifier, password);
      if (typeof window !== 'undefined') window.location.href = '/';
    } catch (err: any) {
      const msg = extractErrorMessage(err, 'Login failed');
      toast(msg, 'error');
    } finally {
      setLoading(false);
    }
  };

  return (
    <form onSubmit={onSubmit} className="space-y-4">
      <Input
        id="identifier"
        label="Username or Email"
        value={identifier}
        onChange={(e) => setIdentifier(e.target.value)}
        placeholder="you@example.com or username"
        required
      />
      <Input
        id="password"
        label="Password"
        type="password"
        value={password}
        onChange={(e) => setPassword(e.target.value)}
        placeholder="••••••••"
        required
      />
      <Button type="submit" full disabled={loading}>{loading ? 'Signing in...' : 'Sign in'}</Button>
    </form>
  );
};

export default LoginForm;
