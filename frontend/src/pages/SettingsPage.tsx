import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import { AuthService } from '../services/auth.service';
import { KeyRotationService } from '../services/keyrotation.service';
import Button from '../components/Button';
import Card from '../components/Card';
import Input from '../components/Input';
import Modal from '../components/Modal';
import toast from 'react-hot-toast';

const SettingsPage: React.FC = () => {
  const navigate = useNavigate();
  const { user, logout } = useAuth();
  const [activeTab, setActiveTab] = useState<'account' | 'security'>('account');
  const [showPasswordModal, setShowPasswordModal] = useState(false);
  const [showAuditLog, setShowAuditLog] = useState(false);
  const [passwordForm, setPasswordForm] = useState({
    currentPassword: '',
    newPassword: '',
    confirmPassword: ''
  });
  const [is2FAEnabled, setIs2FAEnabled] = useState(() => {
    // Load từ localStorage khi component mount
    const saved = localStorage.getItem('is2FAEnabled');
    return saved ? JSON.parse(saved) : true; // Mặc định là bật
  });

  // Lưu trạng thái 2FA vào localStorage mỗi khi thay đổi
  useEffect(() => {
    localStorage.setItem('is2FAEnabled', JSON.stringify(is2FAEnabled));
  }, [is2FAEnabled]);

  const handleChangeMasterPassword = () => {
    setShowPasswordModal(true);
  };

  const handleSubmitPasswordChange = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (passwordForm.newPassword !== passwordForm.confirmPassword) {
      toast.error('Mật khẩu mới không khớp!');
      return;
    }

    if (passwordForm.newPassword.length < 8) {
      toast.error('Mật khẩu phải có ít nhất 8 ký tự!');
      return;
    }

    if (!user?.email) {
      toast.error('Không tìm thấy thông tin user');
      return;
    }

    try {
      toast.loading('Đang thay đổi master password và mã hóa lại dữ liệu...', { duration: 10000 });
      
      await KeyRotationService.changeMasterPassword(
        user.email,
        passwordForm.currentPassword,
        passwordForm.newPassword
      );
      
      toast.dismiss();
      toast.success('Đổi master password thành công! Vui lòng đăng nhập lại.');
      setShowPasswordModal(false);
      setPasswordForm({ currentPassword: '', newPassword: '', confirmPassword: '' });
      
      // Logout after password change
      setTimeout(() => {
        logout();
        navigate('/login');
      }, 2000);
    } catch (error: any) {
      toast.dismiss();
      toast.error(error.message || 'Không thể đổi password');
    }
  };

  const handleToggle2FA = async () => {
    if (!user?.email) return;
    
    try {
      const newState = !is2FAEnabled;
      await AuthService.toggle2FA(user.email, newState);
      setIs2FAEnabled(newState);
      toast.success(newState ? 'Đã bật 2FA' : 'Đã tắt 2FA');
    } catch (error: any) {
      toast.error(error.message || 'Không thể thay đổi cài đặt 2FA');
    }
  };

  const handleViewAuditLog = () => {
    setShowAuditLog(true);
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
              <h1 className="text-xl font-bold text-gray-900">Cài đặt</h1>
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

      <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Tabs */}
        <div className="flex space-x-4 mb-6 border-b">
          {[
            { id: 'account', label: 'Tài khoản', icon: '👤' },
            { id: 'security', label: 'Bảo mật', icon: '🔒' }
          ].map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as any)}
              className={`px-4 py-2 font-medium text-sm border-b-2 transition-colors ${
                activeTab === tab.id
                  ? 'border-blue-600 text-blue-600'
                  : 'border-transparent text-gray-600 hover:text-gray-900'
              }`}
            >
              {tab.icon} {tab.label}
            </button>
          ))}
        </div>

        {/* Account Tab */}
        {activeTab === 'account' && (
          <div className="space-y-6">
            <Card title="Thông tin tài khoản">
              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">Email</label>
                  <Input value={user?.email || ''} disabled />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">User ID</label>
                  <Input value={user?.id || ''} disabled />
                </div>
              </div>
            </Card>
          </div>
        )}

        {/* Security Tab */}
        {activeTab === 'security' && (
          <div className="space-y-6">
            <Card title="Master Password">
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <div>
                    <h4 className="font-medium text-gray-900">Đổi Master Password</h4>
                    <p className="text-sm text-gray-600">Cập nhật master password của bạn</p>
                  </div>
                  <Button onClick={handleChangeMasterPassword}>Đổi password</Button>
                </div>
                <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-4 mt-4">
                  <p className="text-sm text-yellow-800">
                    ⚠️ Đổi master password sẽ yêu cầu đăng nhập lại trên tất cả thiết bị
                  </p>
                </div>
              </div>
            </Card>

            <Card title="Xác thực 2 yếu tố (2FA)">
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <div>
                    <h4 className="font-medium text-gray-900">OTP qua Email</h4>
                    <p className="text-sm text-gray-600">Nhận mã OTP qua email khi đăng nhập</p>
                  </div>
                  <div className="flex items-center space-x-2">
                    <span className={`text-sm font-medium ${is2FAEnabled ? 'text-green-600' : 'text-gray-600'}`}>
                      {is2FAEnabled ? 'Đã bật' : 'Đã tắt'}
                    </span>
                    <button
                      onClick={handleToggle2FA}
                      className={`relative inline-block w-10 h-6 transition duration-200 ease-in-out rounded-full ${
                        is2FAEnabled ? 'bg-green-500' : 'bg-gray-300'
                      }`}
                    >
                      <span className={`absolute left-1 top-1 w-4 h-4 transition duration-200 ease-in-out transform bg-white rounded-full ${
                        is2FAEnabled ? 'translate-x-4' : 'translate-x-0'
                      }`}></span>
                    </button>
                  </div>
                </div>
              </div>
            </Card>

            <Card title="Mã hóa">
              <div className="space-y-3">
                <div className="flex items-center justify-between py-2">
                  <span className="text-sm text-gray-600">Thuật toán mã hóa</span>
                  <span className="text-sm font-medium text-gray-900">AES-256-GCM</span>
                </div>
                <div className="flex items-center justify-between py-2 border-t">
                  <span className="text-sm text-gray-600">Key derivation</span>
                  <span className="text-sm font-medium text-gray-900">PBKDF2 (600,000 iterations)</span>
                </div>
                <div className="flex items-center justify-between py-2 border-t">
                  <span className="text-sm text-gray-600">Zero-Knowledge</span>
                  <span className="text-sm font-medium text-green-600">✓ Đã kích hoạt</span>
                </div>
              </div>
            </Card>

            <Card title="Audit Log">
              <div className="space-y-4">
                <p className="text-sm text-gray-600">Xem lịch sử hoạt động và truy cập vào vault của bạn</p>
                <Button onClick={handleViewAuditLog}>Xem Audit Log</Button>
              </div>
            </Card>
          </div>
        )}


      </div>

      {/* Change Password Modal */}
      <Modal
        isOpen={showPasswordModal}
        onClose={() => setShowPasswordModal(false)}
        title="Đổi Master Password"
      >
        <form onSubmit={handleSubmitPasswordChange} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Master Password hiện tại
            </label>
            <Input
              type="password"
              value={passwordForm.currentPassword}
              onChange={(e) => setPasswordForm({ ...passwordForm, currentPassword: e.target.value })}
              required
              placeholder="Nhập master password hiện tại"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Master Password mới
            </label>
            <Input
              type="password"
              value={passwordForm.newPassword}
              onChange={(e) => setPasswordForm({ ...passwordForm, newPassword: e.target.value })}
              required
              placeholder="Nhập master password mới (tối thiểu 8 ký tự)"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Xác nhận Master Password mới
            </label>
            <Input
              type="password"
              value={passwordForm.confirmPassword}
              onChange={(e) => setPasswordForm({ ...passwordForm, confirmPassword: e.target.value })}
              required
              placeholder="Nhập lại master password mới"
            />
          </div>

          <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-3">
            <p className="text-sm text-yellow-800">
              ⚠️ Sau khi đổi master password, bạn sẽ bị đăng xuất và cần đăng nhập lại với password mới.
            </p>
          </div>

          <div className="flex space-x-3">
            <Button type="button" variant="ghost" fullWidth onClick={() => setShowPasswordModal(false)}>
              Hủy
            </Button>
            <Button type="submit" fullWidth>
              Đổi Password
            </Button>
          </div>
        </form>
      </Modal>

      {/* Audit Log Modal */}
      <Modal
        isOpen={showAuditLog}
        onClose={() => setShowAuditLog(false)}
        title="Audit Log"
      >
        <div className="space-y-4">
          <p className="text-sm text-gray-600">Lịch sử hoạt động gần đây</p>
          
          <div className="space-y-2 max-h-96 overflow-y-auto">
            {[
              { action: 'Đăng nhập', time: '5 phút trước', ip: '192.168.1.100', device: 'Windows • Chrome' },
              { action: 'Tạo vault item', time: '10 phút trước', ip: '192.168.1.100', device: 'Windows • Chrome' },
              { action: 'Cập nhật vault item', time: '15 phút trước', ip: '192.168.1.100', device: 'Windows • Chrome' },
              { action: 'Đăng nhập', time: '2 giờ trước', ip: '192.168.1.101', device: 'iPhone • Safari' },
              { action: 'Đăng xuất', time: '3 giờ trước', ip: '192.168.1.101', device: 'iPhone • Safari' },
            ].map((log, index) => (
              <div key={index} className="p-3 bg-gray-50 rounded-lg">
                <div className="flex items-center justify-between">
                  <div>
                    <h4 className="font-medium text-gray-900">{log.action}</h4>
                    <p className="text-xs text-gray-500">{log.device}</p>
                    <p className="text-xs text-gray-500">IP: {log.ip}</p>
                  </div>
                  <span className="text-xs text-gray-500">{log.time}</span>
                </div>
              </div>
            ))}
          </div>

          <Button fullWidth onClick={() => setShowAuditLog(false)}>
            Đóng
          </Button>
        </div>
      </Modal>
    </div>
  );
};

export default SettingsPage;
