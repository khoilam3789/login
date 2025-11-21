import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import Input from '../components/Input';
import Button from '../components/Button';
import Card from '../components/Card';
import toast from 'react-hot-toast';

const LoginPage: React.FC = () => {
  const navigate = useNavigate();
  const { login } = useAuth();
  const [formData, setFormData] = useState({
    email: '',
    masterPassword: '',
    rememberMe: false
  });
  const [isLoading, setIsLoading] = useState(false);

  // Load saved credentials on mount
  React.useEffect(() => {
    const savedEmail = localStorage.getItem('rememberedEmail');
    const savedPassword = localStorage.getItem('rememberedPassword');
    const rememberMe = localStorage.getItem('rememberMe') === 'true';
    
    if (rememberMe && savedEmail) {
      setFormData({
        email: savedEmail,
        masterPassword: savedPassword || '',
        rememberMe: true
      });
    }
  }, []);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    console.log('🚀 [LoginPage] Form submitted');
    
    if (!formData.email || !formData.masterPassword) {
      toast.error('Vui lòng điền đầy đủ thông tin');
      return;
    }

    try {
      setIsLoading(true);
      console.log('🚀 [LoginPage] Calling login function...');
      
      await login(formData.email, formData.masterPassword);
      
      // Save credentials if remember me is checked
      if (formData.rememberMe) {
        localStorage.setItem('rememberedEmail', formData.email);
        localStorage.setItem('rememberedPassword', formData.masterPassword);
        localStorage.setItem('rememberMe', 'true');
      } else {
        localStorage.removeItem('rememberedEmail');
        localStorage.removeItem('rememberedPassword');
        localStorage.removeItem('rememberMe');
      }
      
      console.log('✅ [LoginPage] Login successful!');
      toast.success('Đăng nhập thành công!');
      navigate('/dashboard');
    } catch (error: any) {
      console.error('❌ [LoginPage] Login error:', error);
      
      const errorMessage = error.message || 'Đăng nhập thất bại';
      
      // Check if it's email verification error
      if (error.response?.data?.code === 'EMAIL_NOT_VERIFIED') {
        toast.error('Vui lòng xác thực email trước khi đăng nhập');
        setTimeout(() => {
          navigate('/email-verification-pending');
        }, 2000);
      } else {
        toast.error(errorMessage);
      }
    } finally {
      setIsLoading(false);
      console.log('🏁 [LoginPage] Login process finished');
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 flex items-center justify-center p-4">
      <div className="w-full max-w-md">
        <div className="text-center mb-8">
          <h1 className="text-4xl font-bold text-gray-900 mb-2">Password Manager</h1>
          <p className="text-gray-600">Quản lý mật khẩu an toàn với Zero-Knowledge</p>
        </div>

        <Card>
          <form onSubmit={handleSubmit} className="space-y-4">
            <h2 className="text-2xl font-semibold text-gray-900 mb-6">Đăng nhập</h2>
            
            <Input
              type="email"
              label="Email"
              placeholder="your@email.com"
              value={formData.email}
              onChange={(e) => setFormData({ ...formData, email: e.target.value })}
              icon={
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M16 12a4 4 0 10-8 0 4 4 0 008 0zm0 0v1.5a2.5 2.5 0 005 0V12a9 9 0 10-9 9m4.5-1.206a8.959 8.959 0 01-4.5 1.207" />
                </svg>
              }
              required
            />

            <Input
              type="password"
              label="Master Password"
              placeholder="••••••••"
              value={formData.masterPassword}
              onChange={(e) => setFormData({ ...formData, masterPassword: e.target.value })}
              helperText="Master password không bao giờ được gửi đến server"
              icon={
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                </svg>
              }
              required
            />

            <div className="flex items-center">
              <input
                type="checkbox"
                id="rememberMe"
                checked={formData.rememberMe}
                onChange={(e) => setFormData({ ...formData, rememberMe: e.target.checked })}
                className="w-4 h-4 text-blue-600 bg-gray-100 border-gray-300 rounded focus:ring-blue-500 focus:ring-2"
              />
              <label htmlFor="rememberMe" className="ml-2 text-sm text-gray-700 cursor-pointer">
                Ghi nhớ đăng nhập
              </label>
            </div>

            <Button type="submit" fullWidth isLoading={isLoading}>
              Đăng nhập
            </Button>

            <div className="text-center mt-4">
              <Link to="/register" className="text-blue-600 hover:text-blue-700 text-sm">
                Chưa có tài khoản? Đăng ký ngay
              </Link>
            </div>
          </form>
        </Card>

        <div className="mt-6 text-center">
          <div className="flex items-center justify-center space-x-2 text-sm text-gray-600">
            <svg className="w-5 h-5 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
            </svg>
            <span>AES-256-GCM • PBKDF2 • Zero-Knowledge</span>
          </div>
        </div>
      </div>
    </div>
  );
};

export default LoginPage;
