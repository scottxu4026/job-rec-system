export const extractErrorMessage = (err: any, fallback = 'Something went wrong') => {
  const status = err?.response?.status;
  const backend = err?.response?.data?.message;
  if (status === 401) return 'Invalid credentials';
  if (status === 403) return 'Forbidden';
  if (status === 422 && backend) return backend;
  return backend || fallback;
};


