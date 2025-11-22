import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import Button from '../components/Button';
import Card from '../components/Card';
import Modal from '../components/Modal';
import Input from '../components/Input';
import OTPService, { ExternalSecret } from '../services/otp.service';
import toast from 'react-hot-toast';

const ExternalOTPPage: React.FC = () => {
  const navigate = useNavigate();
  const { user, logout } = useAuth();
  const [secrets, setSecrets] = useState<ExternalSecret[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [showModal, setShowModal] = useState(false);
  const [editingSecret, setEditingSecret] = useState<ExternalSecret | null>(null);
  const [formData, setFormData] = useState({
    label: '',
    secret: '',
    issuer: '',
    algorithm: 'SHA1' as 'SHA1' | 'SHA256' | 'SHA512',
    digits: 6 as 6 | 8,
    period: 30
  });
  const [otpCodes, setOtpCodes] = useState<{ [key: string]: string }>({});
  const [countdown, setCountdown] = useState(30);

  useEffect(() => {
    loadSecrets();
  }, []);

  useEffect(() => {
    const timer = setInterval(() => {
      const now = Math.floor(Date.now() / 1000);
      const remaining = 30 - (now % 30);
      setCountdown(remaining);

      // Generate OTP codes
      if (secrets.length > 0) {
        generateAllOTPCodes();
      }
    }, 1000);

    return () => clearInterval(timer);
  }, [secrets]);

  const loadSecrets = async () => {
    try {
      setIsLoading(true);
      const data = await OTPService.getExternalSecrets();
      setSecrets(data || []);
      generateAllOTPCodes();
    } catch (error: any) {
      toast.error(error.message || 'Không thể tải dữ liệu');
      setSecrets([]); // Ensure secrets is always an array
    } finally {
      setIsLoading(false);
    }
  };

  const generateAllOTPCodes = async () => {
    const codes: { [key: string]: string } = {};
    for (const secret of secrets) {
      try {
        // Fetch the actual secret from backend
        const encryptedSecret = await OTPService.getExternalSecret(secret.id);
        
        // TODO: Decrypt encryptedSecret with DEK here
        // For now, use it directly (assuming it's not encrypted yet)
        const code = await OTPService.generateTOTP(encryptedSecret, secret.period, secret.digits);
        codes[secret.id] = code;
      } catch (error) {
        console.error('Generate OTP error:', error);
        codes[secret.id] = '------';
      }
    }
    setOtpCodes(codes);
  };

  const handleOpenModal = (secret?: ExternalSecret) => {
    if (secret) {
      setEditingSecret(secret);
      setFormData({
        label: secret.label,
        secret: secret.secret,
        issuer: secret.issuer || '',
        algorithm: secret.algorithm,
        digits: secret.digits,
        period: secret.period
      });
    } else {
      setEditingSecret(null);
      setFormData({
        label: '',
        secret: '',
        issuer: '',
        algorithm: 'SHA1',
        digits: 6,
        period: 30
      });
    }
    setShowModal(true);
  };

  const handleCloseModal = () => {
    setShowModal(false);
    setEditingSecret(null);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    try {
      if (editingSecret) {
        await OTPService.updateExternalSecret(editingSecret.id, formData);
        toast.success('Cập nhật thành công!');
      } else {
        await OTPService.addExternalSecret(formData);
        toast.success('Thêm secret thành công!');
      }
      handleCloseModal();
      loadSecrets();
    } catch (error: any) {
      toast.error(error.message || 'Có lỗi xảy ra');
    }
  };

  const handleDelete = async (id: string) => {
    if (confirm('Bạn có chắc muốn xóa secret này?')) {
      try {
        await OTPService.deleteExternalSecret(id);
        toast.success('Xóa thành công!');
        loadSecrets();
      } catch (error: any) {
        toast.error(error.message || 'Không thể xóa');
      }
    }
  };

  const handleCopyCode = async (code: string) => {
    try {
      await navigator.clipboard.writeText(code);
      toast.success('Đã sao chép mã OTP!');
    } catch (error) {
      toast.error('Không thể sao chép');
    }
  };

  return (
    <div className="min-h-screen bg-gray-50">
      <nav className="bg-white shadow-sm">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center h-16">
            <div className="flex items-center space-x-4">
              <button onClick={() => navigate('/dashboard')} className="text-gray-600 hover:text-gray-900">
                <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 19l-7-7m0 0l7-7m-7 7h18" />
                </svg>
              </button>
              <h1 className="text-xl font-bold text-gray-900">OTP Bên ngoài</h1>
            </div>
            <div className="flex items-center space-x-4">
              <span className="text-sm text-gray-600">{user?.email}</span>
              <Button variant="ghost" size="sm" onClick={() => logout()}>
                Đăng xuất
              </Button>
            </div>
          </div>
        </div>
      </nav>

      <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="flex justify-between items-center mb-6">
          <div>
            <h2 className="text-2xl font-bold text-gray-900">Quản lý 2FA bên ngoài</h2>
            <p className="text-gray-600 mt-1">Lưu trữ và tạo mã OTP cho các dịch vụ khác</p>
          </div>
          <Button onClick={() => handleOpenModal()}>
            + Thêm Secret
          </Button>
        </div>

        {/* Countdown */}
        <div className="mb-6">
          <Card>
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-600">Mã sẽ làm mới sau:</span>
              <div className="flex items-center space-x-3">
                <div className="relative w-16 h-16">
                  <svg className="transform -rotate-90 w-16 h-16">
                    <circle
                      cx="32"
                      cy="32"
                      r="28"
                      stroke="currentColor"
                      strokeWidth="4"
                      fill="none"
                      className="text-gray-200"
                    />
                    <circle
                      cx="32"
                      cy="32"
                      r="28"
                      stroke="currentColor"
                      strokeWidth="4"
                      fill="none"
                      strokeDasharray={`${2 * Math.PI * 28}`}
                      strokeDashoffset={`${2 * Math.PI * 28 * (1 - countdown / 30)}`}
                      className="text-blue-600 transition-all duration-1000"
                    />
                  </svg>
                  <div className="absolute inset-0 flex items-center justify-center">
                    <span className="text-xl font-bold text-gray-900">{countdown}</span>
                  </div>
                </div>
              </div>
            </div>
          </Card>
        </div>

        {/* Secrets List */}
        {isLoading ? (
          <div className="flex justify-center py-12">
            <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
          </div>
        ) : (!secrets || secrets.length === 0) ? (
          <Card>
            <div className="text-center py-12">
              <svg className="mx-auto h-24 w-24 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 11c0 3.517-1.009 6.799-2.753 9.571m-3.44-2.04l.054-.09A13.916 13.916 0 008 11a4 4 0 118 0c0 1.017-.07 2.019-.203 3m-2.118 6.844A21.88 21.88 0 0015.171 17m3.839 1.132c.645-2.266.99-4.659.99-7.132A8 8 0 008 4.07M3 15.364c.64-1.319 1-2.8 1-4.364 0-1.457.39-2.823 1.07-4" />
              </svg>
              <h3 className="mt-4 text-lg font-medium text-gray-900">Chưa có secret nào</h3>
              <p className="mt-2 text-sm text-gray-600">
                Thêm secret để bắt đầu tạo mã OTP cho các dịch vụ 2FA
              </p>
            </div>
          </Card>
        ) : (
          <div className="space-y-4">
            {secrets.map((secret) => (
              <Card key={secret.id}>
                <div className="flex items-center justify-between">
                  <div className="flex-1">
                    <h3 className="font-semibold text-gray-900">{secret.label}</h3>
                    {secret.issuer && (
                      <p className="text-sm text-gray-600">{secret.issuer}</p>
                    )}
                    <div className="mt-2 flex items-center space-x-2">
                      <span className="text-3xl font-mono font-bold text-blue-600 tracking-wider">
                        {otpCodes[secret.id] || '------'}
                      </span>
                      <button
                        onClick={() => handleCopyCode(otpCodes[secret.id])}
                        className="p-2 text-gray-600 hover:text-blue-600"
                      >
                        <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                        </svg>
                      </button>
                    </div>
                    <p className="text-xs text-gray-500 mt-1">
                      {secret.algorithm} • {secret.digits} chữ số • {secret.period}s
                    </p>
                  </div>
                  <div className="flex flex-col space-y-2">
                    <Button variant="secondary" size="sm" onClick={() => handleOpenModal(secret)}>
                      Sửa
                    </Button>
                    <Button variant="danger" size="sm" onClick={() => handleDelete(secret.id)}>
                      Xóa
                    </Button>
                  </div>
                </div>
              </Card>
            ))}
          </div>
        )}

        {/* Info */}
        <div className="mt-6 bg-blue-50 border border-blue-200 rounded-lg p-4">
          <h3 className="text-sm font-semibold text-blue-900 mb-2 flex items-center">
            <svg className="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            Lưu trữ Secret 2FA bên ngoài
          </h3>
          <p className="text-sm text-blue-800">
            Thêm secret từ các dịch vụ như Google, GitHub, AWS... để tạo mã OTP ngay trong ứng dụng. 
            Secret được mã hóa và chỉ bạn mới có thể truy cập.
          </p>
        </div>
      </div>

      {/* Add/Edit Modal */}
      <Modal isOpen={showModal} onClose={handleCloseModal} title={editingSecret ? 'Chỉnh sửa Secret' : 'Thêm Secret mới'}>
        <form onSubmit={handleSubmit} className="space-y-4">
          <Input
            label="Nhãn *"
            value={formData.label}
            onChange={(e) => setFormData({ ...formData, label: e.target.value })}
            placeholder="Google Account"
            required
          />

          <Input
            label="Issuer (Tùy chọn)"
            value={formData.issuer}
            onChange={(e) => setFormData({ ...formData, issuer: e.target.value })}
            placeholder="Google"
          />

          <Input
            label="Secret Key *"
            value={formData.secret}
            onChange={(e) => setFormData({ ...formData, secret: e.target.value })}
            placeholder="JBSWY3DPEHPK3PXP"
            helperText="Secret key (Base32) từ dịch vụ 2FA"
            required
          />

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Thuật toán</label>
            <select
              value={formData.algorithm}
              onChange={(e) => setFormData({ ...formData, algorithm: e.target.value as any })}
              className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              <option value="SHA1">SHA1</option>
              <option value="SHA256">SHA256</option>
              <option value="SHA512">SHA512</option>
            </select>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Số chữ số</label>
            <select
              value={formData.digits}
              onChange={(e) => setFormData({ ...formData, digits: parseInt(e.target.value) as any })}
              className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              <option value={6}>6</option>
              <option value={8}>8</option>
            </select>
          </div>

          <Input
            label="Chu kỳ (giây)"
            type="number"
            value={formData.period.toString()}
            onChange={(e) => setFormData({ ...formData, period: parseInt(e.target.value) })}
            min={15}
            max={60}
          />

          <div className="flex space-x-2 pt-4">
            <Button type="submit" fullWidth>
              {editingSecret ? 'Cập nhật' : 'Thêm Secret'}
            </Button>
            <Button type="button" variant="secondary" fullWidth onClick={handleCloseModal}>
              Hủy
            </Button>
          </div>
        </form>
      </Modal>
    </div>
  );
};

export default ExternalOTPPage;
