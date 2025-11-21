import React from 'react';
import { Link } from 'react-router-dom';
import Card from '../components/Card';

const EmailVerificationPendingPage: React.FC = () => {
  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 flex items-center justify-center p-4">
      <div className="w-full max-w-md">
        <div className="text-center mb-8">
          <h1 className="text-4xl font-bold text-gray-900 mb-2">Password Manager</h1>
          <p className="text-gray-600">Xác thực email của bạn</p>
        </div>

        <Card>
          <div className="text-center space-y-6">
            {/* Email Icon */}
            <div className="flex justify-center">
              <div className="w-20 h-20 bg-blue-100 rounded-full flex items-center justify-center">
                <svg className="w-10 h-10 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
                </svg>
              </div>
            </div>

            {/* Title */}
            <div>
              <h2 className="text-2xl font-semibold text-gray-900 mb-2">
                Kiểm tra email của bạn
              </h2>
              <p className="text-gray-600">
                Chúng tôi đã gửi một email xác thực đến địa chỉ email của bạn.
              </p>
            </div>

            {/* Instructions */}
            <div className="bg-blue-50 border border-blue-200 rounded-lg p-4 text-left">
              <h3 className="text-sm font-semibold text-blue-900 mb-2 flex items-center">
                <svg className="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
                Các bước tiếp theo:
              </h3>
              <ol className="text-sm text-blue-800 space-y-2 list-decimal list-inside">
                <li>Mở email từ Password Manager trong hộp thư đến của bạn</li>
                <li>Nhấn vào nút "Xác Thực Email" trong email</li>
                <li>Sau khi xác thực thành công, quay lại đây để đăng nhập</li>
              </ol>
            </div>

            {/* Warning */}
            <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-4">
              <p className="text-sm text-yellow-800">
                ⚠️ Link xác thực có hiệu lực trong <strong>24 giờ</strong>. 
                Nếu không thấy email, vui lòng kiểm tra thư mục spam.
              </p>
            </div>

            {/* Action Buttons */}
            <div className="space-y-3 pt-4">
              <Link
                to="/login"
                className="block w-full bg-blue-600 hover:bg-blue-700 text-white font-medium py-3 px-4 rounded-lg transition-colors"
              >
                Đã xác thực? Đăng nhập ngay
              </Link>

              <Link
                to="/resend-verification"
                className="block w-full text-blue-600 hover:text-blue-700 font-medium py-2 transition-colors"
              >
                Gửi lại email xác thực
              </Link>
            </div>
          </div>
        </Card>

        {/* Additional Info */}
        <div className="mt-6 text-center">
          <p className="text-sm text-gray-600">
            Cần trợ giúp?{' '}
            <Link to="/support" className="text-blue-600 hover:text-blue-700 font-medium">
              Liên hệ hỗ trợ
            </Link>
          </p>
        </div>
      </div>
    </div>
  );
};

export default EmailVerificationPendingPage;
