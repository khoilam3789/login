import React, { useState, useEffect } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import Button from '../components/Button';
import Card from '../components/Card';
import Input from '../components/Input';
import toast from 'react-hot-toast';
import { AuthService } from '../services/auth.service';

const OTPVerifyPage: React.FC = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const { tempToken, email } = location.state || {};
  
  const [otp, setOtp] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [countdown, setCountdown] = useState(600); // 10 minutes in seconds
  const [canResend, setCanResend] = useState(false);

  useEffect(() => {
    if (!tempToken || !email) {
      toast.error('Invalid access');
      navigate('/login');
      return;
    }

    // Countdown timer
    const timer = setInterval(() => {
      setCountdown((prev) => {
        if (prev <= 1) {
          clearInterval(timer);
          setCanResend(true);
          return 0;
        }
        return prev - 1;
      });
    }, 1000);

    return () => clearInterval(timer);
  }, [tempToken, email, navigate]);

  const formatTime = (seconds: number) => {
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${mins}:${secs.toString().padStart(2, '0')}`;
  };

  const handleVerifyOTP = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (otp.length !== 6) {
      toast.error('OTP phải có 6 chữ số');
      return;
    }

    setIsLoading(true);
    try {
      const { authResponse, dek } = await AuthService.verifyOTP(tempToken, otp);
      
      // Set auth context (needed for protected routes)
      // Store in localStorage was already done by AuthService.verifyOTP
      
      toast.success('Xác thực thành công!');
      
      // Redirect to dashboard
      window.location.href = '/dashboard';
    } catch (error: any) {
      toast.error(error.message || 'OTP không hợp lệ');
    } finally {
      setIsLoading(false);
    }
  };

  const handleResendOTP = async () => {
    setIsLoading(true);
    try {
      await AuthService.resendOTP(tempToken);
      toast.success('Đã gửi lại OTP!');
      setCountdown(600);
      setCanResend(false);
    } catch (error: any) {
      toast.error(error.message || 'Không thể gửi lại OTP');
    } finally {
      setIsLoading(false);
    }
  };

  const handleBackToLogin = () => {
    navigate('/login');
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 flex items-center justify-center p-4">
      <Card className="w-full max-w-md">
        <div className="text-center mb-6">
          <div className="w-16 h-16 bg-blue-100 rounded-full flex items-center justify-center mx-auto mb-4">
            <svg className="w-8 h-8 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
            </svg>
          </div>
          <h2 className="text-2xl font-bold text-gray-900 mb-2">Xác thực 2 yếu tố</h2>
          <p className="text-sm text-gray-600">
            Mã OTP đã được gửi đến email
          </p>
          <p className="text-sm font-medium text-blue-600">{email}</p>
        </div>

        <form onSubmit={handleVerifyOTP} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Nhập mã OTP (6 chữ số)
            </label>
            <Input
              type="text"
              value={otp}
              onChange={(e) => setOtp(e.target.value.replace(/\D/g, '').slice(0, 6))}
              placeholder="123456"
              maxLength={6}
              className="text-center text-2xl tracking-widest"
              autoFocus
              required
            />
          </div>

          <div className="flex items-center justify-between text-sm">
            <span className="text-gray-600">
              {countdown > 0 ? (
                <>Mã hết hạn sau: <span className="font-medium text-blue-600">{formatTime(countdown)}</span></>
              ) : (
                <span className="text-red-600 font-medium">Mã đã hết hạn</span>
              )}
            </span>
          </div>

          <Button
            type="submit"
            fullWidth
            disabled={isLoading || otp.length !== 6}
          >
            {isLoading ? 'Đang xác thực...' : 'Xác thực'}
          </Button>

          <div className="space-y-2">
            <Button
              type="button"
              variant="ghost"
              fullWidth
              onClick={handleResendOTP}
              disabled={isLoading || !canResend}
            >
              {canResend ? 'Gửi lại mã OTP' : 'Gửi lại mã'}
            </Button>

            <Button
              type="button"
              variant="ghost"
              fullWidth
              onClick={handleBackToLogin}
            >
              Quay lại đăng nhập
            </Button>
          </div>
        </form>

        <div className="mt-6 p-4 bg-blue-50 rounded-lg">
          <p className="text-xs text-blue-800">
            💡 <strong>Mẹo:</strong> Kiểm tra cả hộp thư spam/junk nếu không thấy email.
          </p>
        </div>
      </Card>
    </div>
  );
};

export default OTPVerifyPage;
