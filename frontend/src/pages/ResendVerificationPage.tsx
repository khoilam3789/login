import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import apiClient from '../services/api.service';
import Card from '../components/Card';
import Input from '../components/Input';
import Button from '../components/Button';
import toast from 'react-hot-toast';

const ResendVerificationPage: React.FC = () => {
  const [email, setEmail] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [emailSent, setEmailSent] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!email) {
      toast.error('Please enter your email');
      return;
    }

    try {
      setIsLoading(true);
      await apiClient.post('/auth/resend-verification', { email });
      
      setEmailSent(true);
      toast.success('Verification email sent! Please check your inbox.');
    } catch (error: any) {
      toast.error(error.response?.data?.message || 'Failed to send verification email');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 flex items-center justify-center p-4">
      <div className="w-full max-w-md">
        <div className="text-center mb-8">
          <h1 className="text-4xl font-bold text-gray-900 mb-2">Password Manager</h1>
          <p className="text-gray-600">Resend Verification Email</p>
        </div>

        <Card>
          {!emailSent ? (
            <form onSubmit={handleSubmit} className="space-y-4">
              <h2 className="text-2xl font-semibold text-gray-900 mb-6">Verify Your Email</h2>

              <p className="text-gray-600 mb-4">
                Enter your email address and we'll send you a new verification link.
              </p>

              <Input
                type="email"
                label="Email"
                placeholder="your@email.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                icon={
                  <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M16 12a4 4 0 10-8 0 4 4 0 008 0zm0 0v1.5a2.5 2.5 0 005 0V12a9 9 0 10-9 9m4.5-1.206a8.959 8.959 0 01-4.5 1.207" />
                  </svg>
                }
                required
              />

              <Button
                type="submit"
                variant="primary"
                isLoading={isLoading}
                className="w-full"
              >
                Send Verification Email
              </Button>

              <div className="text-center">
                <Link to="/login" className="text-blue-600 hover:text-blue-700 text-sm">
                  Back to Login
                </Link>
              </div>
            </form>
          ) : (
            <div className="text-center py-8">
              <div className="w-16 h-16 bg-green-100 rounded-full flex items-center justify-center mx-auto mb-4">
                <svg className="w-8 h-8 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
                </svg>
              </div>
              <h2 className="text-xl font-semibold text-gray-900 mb-2">Email Sent!</h2>
              <p className="text-gray-600 mb-6">
                We've sent a verification link to <strong>{email}</strong>
              </p>
              <p className="text-sm text-gray-500 mb-6">
                Please check your inbox and spam folder.
              </p>
              <Link to="/login">
                <Button variant="primary" className="w-full">
                  Go to Login
                </Button>
              </Link>
            </div>
          )}
        </Card>
      </div>
    </div>
  );
};

export default ResendVerificationPage;
