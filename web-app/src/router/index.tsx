import React from 'react';
import { createBrowserRouter, RouterProvider } from 'react-router-dom';
import Layout from '../components/common/Layout';
import HomePage from '../pages/Home';
import LoginPage from '../pages/Login';
import RegisterPage from '../pages/Register';
import VerifyEmailPage from '../pages/VerifyEmail';
import ForgotPasswordPage from '../pages/ForgotPassword';
import ResetPasswordPage from '../pages/ResetPassword';
import CompleteOAuthPage from '../pages/CompleteOAuth';
import LinkOAuthPage from '../pages/LinkOAuth';
import MePage from '../pages/Me';
import RequireAuth from '../components/common/RequireAuth';

const router = createBrowserRouter([
  { path: '/', element: <Layout><HomePage /></Layout> },
  { path: '/login', element: <LoginPage /> },
  { path: '/register', element: <RegisterPage /> },
  { path: '/verify', element: <VerifyEmailPage /> },
  { path: '/forgot-password', element: <ForgotPasswordPage /> },
  { path: '/reset-password', element: <ResetPasswordPage /> },
  { path: '/complete-oauth', element: <CompleteOAuthPage /> },
  { path: '/link-oauth', element: <LinkOAuthPage /> },
  { path: '/me', element: <RequireAuth><Layout><MePage /></Layout></RequireAuth> },
  { path: '*', element: <Layout><div>Not Found</div></Layout> },
]);

export const AppRouter: React.FC = () => <RouterProvider router={router} />;


