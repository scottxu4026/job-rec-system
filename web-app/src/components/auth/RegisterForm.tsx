import React, { useState } from 'react';
import { post } from '../../services/api';
import { useToast } from '../common/Toast';
import { extractErrorMessage } from '../../utils/errors';
import Input from '../ui/Input';
import Button from '../ui/Button';

const fieldNames = ['username', 'email', 'password', 'confirmPassword', 'firstName', 'lastName'] as const;

type FieldName = typeof fieldNames[number];

type FieldErrors = Partial<Record<FieldName, string>> & { general?: string };

const RegisterForm: React.FC = () => {
  const [values, setValues] = useState({
    username: '',
    email: '',
    password: '',
    confirmPassword: '',
    firstName: '',
    lastName: '',
    termsAccepted: false,
  });
  const [errors, setErrors] = useState<FieldErrors>({});
  const [success, setSuccess] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const { toast } = useToast();

  const setField = (name: keyof typeof values, value: string | boolean) => {
    setValues((prev) => {
      const next = { ...prev, [name]: value } as typeof values;
      // Live password validation
      const pwd = next.password;
      const weak = !pwd || pwd.length < 8 || !/[a-z]/.test(pwd) || !/[A-Z]/.test(pwd) || !/[0-9]/.test(pwd) || !/[^A-Za-z0-9]/.test(pwd);
      let pwdError: string | undefined;
      if (weak) pwdError = 'Use 8+ chars with upper, lower, number, symbol.';
      if (next.confirmPassword && next.password !== next.confirmPassword) pwdError = 'Passwords do not match';
      setErrors((e) => ({ ...e, password: pwdError }));
      if (name !== 'password' && name !== 'confirmPassword' && name in errors) {
        setErrors((e) => ({ ...e, [name as FieldName]: undefined }));
      }
      return next;
    });
  };

  const parseError = (message: string): FieldErrors => {
    // Backend returns first invalid field as "field: reason" for validation errors (422)
    const m = message.match(/^(\w+):\s*(.*)$/);
    if (m) {
      const field = m[1] as FieldName;
      const reason = m[2];
      if (fieldNames.includes(field)) {
        return { [field]: reason } as FieldErrors;
      }
    }
    return { general: message };
  };

  const onSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (loading) return;
    setLoading(true);
    setErrors({});
    setSuccess(null);
    try {
      // Client-side password policy and confirmation
      const pwd = values.password;
      const weak = !pwd || pwd.length < 8 || !/[a-z]/.test(pwd) || !/[A-Z]/.test(pwd) || !/[0-9]/.test(pwd) || !/[^A-Za-z0-9]/.test(pwd);
      if (weak) throw new Error('Use 8+ chars with upper, lower, number, symbol.');
      if (values.password !== values.confirmPassword) {
        setErrors((prev) => ({ ...prev, password: 'Passwords do not match' }));
        throw new Error('Passwords do not match');
      }
      const res = await post('/auth/register', values);
      const msg = res.status === 202 ? 'Verification email sent' : 'Registered';
      setSuccess(msg);
      toast(msg, 'success');
    } catch (err: any) {
      const status = err?.response?.status;
      const backendMsg = extractErrorMessage(err, 'Registration failed');
      if (status === 422) setErrors(parseError(backendMsg)); else setErrors((prev) => ({ ...prev, password: err?.message || undefined, general: backendMsg }));
      toast(err?.message || backendMsg, 'error');
    } finally {
      setLoading(false);
    }
  };

  return (
    <form onSubmit={onSubmit} className="space-y-4">
      {success && (
        <div className="rounded-md bg-green-50 text-green-800 px-3 py-2 text-sm">{success}</div>
      )}
      {errors.general && (
        <div className="rounded-md bg-red-50 text-red-700 px-3 py-2 text-sm">{errors.general}</div>
      )}
      <Input id="username" label="Username" value={values.username} onChange={(e) => setField('username', e.target.value)} placeholder="yourname" error={errors.username} required />

      <Input id="email" label="Email" type="email" value={values.email} onChange={(e) => setField('email', e.target.value)} placeholder="you@example.com" error={errors.email} required />

      <Input id="password" label="Password" type="password" value={values.password} onChange={(e) => setField('password', e.target.value)} placeholder="••••••••" error={errors.password} required withToggle />
      <Input id="confirmPassword" label="Confirm password" type="password" value={values.confirmPassword} onChange={(e) => setField('confirmPassword', e.target.value)} placeholder="••••••••" required withToggle />
      <p className="text-xs text-gray-500">Use at least 8 characters with uppercase, lowercase, number, and symbol.</p>

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
        <Input id="firstName" label="First name" value={values.firstName} onChange={(e) => setField('firstName', e.target.value)} placeholder="Ada" error={errors.firstName} required />
        <Input id="lastName" label="Last name" value={values.lastName} onChange={(e) => setField('lastName', e.target.value)} placeholder="Lovelace" error={errors.lastName} required />
      </div>

      <div className="flex items-center">
        <input
          id="terms"
          type="checkbox"
          checked={values.termsAccepted}
          onChange={(e) => setField('termsAccepted', e.target.checked)}
          className="h-4 w-4 rounded border-gray-300 text-blue-600 focus:ring-blue-500"
          required
        />
        <label htmlFor="terms" className="ml-2 text-sm text-gray-700">I accept the Terms of Service</label>
      </div>

      <Button type="submit" full disabled={loading}>{loading ? 'Creating account...' : 'Create account'}</Button>
    </form>
  );
};

export default RegisterForm;
