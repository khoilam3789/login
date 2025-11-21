import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import Input from '../components/Input';
import Button from '../components/Button';
import Card from '../components/Card';
import ClientCryptoService from '../services/crypto.service';
import toast from 'react-hot-toast';

const RegisterPage: React.FC = () => {
  const navigate = useNavigate();
  const { register } = useAuth();
  const [formData, setFormData] = useState({
    email: '',
    masterPassword: '',
    confirmPassword: ''
  });
  const [isLoading, setIsLoading] = useState(false);

  const passwordStrength = formData.masterPassword
    ? ClientCryptoService.calculatePasswordStrength(formData.masterPassword)
    : null;

  const strengthColor = {
    weak: 'bg-red-500',
    medium: 'bg-yellow-500',
    strong: 'bg-blue-500',
    very_strong: 'bg-green-500'
  };

  const strengthLabel = {
    weak: 'Yếu',
    medium: 'Trung bình',
    strong: 'Mạnh',
    very_strong: 'Rất mạnh'
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!formData.email || !formData.masterPassword || !formData.confirmPassword) {
      toast.error('Vui lòng điền đầy đủ thông tin');
      return;
    }

    if (formData.masterPassword !== formData.confirmPassword) {
      toast.error('Mật khẩu xác nhận không khớp');
      return;
    }

    if (passwordStrength && passwordStrength.label === 'weak') {
      toast.error('Mật khẩu quá yếu, vui lòng chọn mật khẩu mạnh hơn');
      return;
    }

    try {
      setIsLoading(true);
      await register(formData.email, formData.masterPassword);
      toast.success('Đăng ký thành công!');
      navigate('/email-verification-pending');
    } catch (error: any) {
      toast.error(error.message || 'Đăng ký thất bại');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 flex items-center justify-center p-4">
      <div className="w-full max-w-md">
        <div className="text-center mb-8">
          <h1 className="text-4xl font-bold text-gray-900 mb-2">Password Manager</h1>
          <p className="text-gray-600">Tạo tài khoản và bảo vệ mật khẩu của bạn</p>
        </div>

        <Card>
          <form onSubmit={handleSubmit} className="space-y-4">
            <h2 className="text-2xl font-semibold text-gray-900 mb-6">Đăng ký</h2>

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

            <div>
              <Input
                type="password"
                label="Master Password"
                placeholder="••••••••"
                value={formData.masterPassword}
                onChange={(e) => setFormData({ ...formData, masterPassword: e.target.value })}
                icon={
                  <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                  </svg>
                }
                required
              />

              {passwordStrength && (
                <div className="mt-2">
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-sm text-gray-600">Độ mạnh:</span>
                    <span className={`text-sm font-medium ${
                      passwordStrength.label === 'weak' ? 'text-red-600' :
                      passwordStrength.label === 'medium' ? 'text-yellow-600' :
                      passwordStrength.label === 'strong' ? 'text-blue-600' :
                      'text-green-600'
                    }`}>
                      {strengthLabel[passwordStrength.label]}
                    </span>
                  </div>
                  <div className="w-full bg-gray-200 rounded-full h-2">
                    <div
                      className={`h-2 rounded-full transition-all ${strengthColor[passwordStrength.label]}`}
                      style={{ width: `${(passwordStrength.score / 7) * 100}%` }}
                    ></div>
                  </div>
                  {passwordStrength.feedback.length > 0 && (
                    <ul className="mt-2 text-sm text-gray-600 list-disc list-inside">
                      {passwordStrength.feedback.map((item, index) => (
                        <li key={index}>{item}</li>
                      ))}
                    </ul>
                  )}
                </div>
              )}

              <p className="mt-1 text-xs text-gray-500">
                ⚠️ Master password không thể khôi phục. Hãy ghi nhớ hoặc lưu ở nơi an toàn!
              </p>
            </div>

            <Input
              type="password"
              label="Xác nhận Master Password"
              placeholder="••••••••"
              value={formData.confirmPassword}
              onChange={(e) => setFormData({ ...formData, confirmPassword: e.target.value })}
              error={
                formData.confirmPassword && formData.masterPassword !== formData.confirmPassword
                  ? 'Mật khẩu không khớp'
                  : undefined
              }
              icon={
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
              }
              required
            />

            <Button type="submit" fullWidth isLoading={isLoading}>
              Đăng ký
            </Button>

            <div className="text-center mt-4">
              <Link to="/login" className="text-blue-600 hover:text-blue-700 text-sm">
                Đã có tài khoản? Đăng nhập
              </Link>
            </div>
          </form>
        </Card>

        <div className="mt-6 bg-blue-50 border border-blue-200 rounded-lg p-4">
          <h3 className="text-sm font-semibold text-blue-900 mb-2 flex items-center">
            <svg className="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            Zero-Knowledge Architecture
          </h3>
          <p className="text-sm text-blue-800">
            Master password chỉ tồn tại trên trình duyệt của bạn và không bao giờ được gửi đến server. 
            Dữ liệu được mã hóa hoàn toàn trước khi lưu trữ.
          </p>
        </div>
      </div>
    </div>
  );
};

export default RegisterPage;
