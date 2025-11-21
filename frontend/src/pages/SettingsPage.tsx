import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import Button from '../components/Button';
import Card from '../components/Card';
import Input from '../components/Input';
import toast from 'react-hot-toast';

const SettingsPage: React.FC = () => {
  const navigate = useNavigate();
  const { user, logout } = useAuth();
  const [activeTab, setActiveTab] = useState<'account' | 'security' | 'sessions'>('account');

  const handleExportVault = () => {
    toast.success('Chức năng đang phát triển');
  };

  const handleImportVault = () => {
    toast.success('Chức năng đang phát triển');
  };

  const handleChangeMasterPassword = () => {
    toast.success('Chức năng đang phát triển');
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
            { id: 'security', label: 'Bảo mật', icon: '🔒' },
            { id: 'sessions', label: 'Phiên làm việc', icon: '📱' }
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

            <Card title="Quản lý dữ liệu">
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <div>
                    <h4 className="font-medium text-gray-900">Xuất Vault</h4>
                    <p className="text-sm text-gray-600">Tải xuống tất cả dữ liệu trong vault (định dạng JSON mã hóa)</p>
                  </div>
                  <Button onClick={handleExportVault}>Xuất</Button>
                </div>
                <div className="flex items-center justify-between pt-4 border-t">
                  <div>
                    <h4 className="font-medium text-gray-900">Nhập Vault</h4>
                    <p className="text-sm text-gray-600">Nhập dữ liệu từ file backup hoặc ứng dụng khác</p>
                  </div>
                  <Button onClick={handleImportVault}>Nhập</Button>
                </div>
              </div>
            </Card>

            <Card title="Xóa tài khoản">
              <div className="space-y-4">
                <div className="bg-red-50 border border-red-200 rounded-lg p-4">
                  <p className="text-sm text-red-800">
                    ⚠️ Xóa tài khoản sẽ xóa vĩnh viễn tất cả dữ liệu của bạn. Hành động này không thể hoàn tác.
                  </p>
                </div>
                <Button variant="danger">Xóa tài khoản</Button>
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
                    <span className="text-sm text-green-600 font-medium">Đã bật</span>
                    <div className="relative inline-block w-10 h-6 transition duration-200 ease-in-out bg-green-500 rounded-full">
                      <span className="absolute left-1 top-1 w-4 h-4 transition duration-200 ease-in-out transform translate-x-4 bg-white rounded-full"></span>
                    </div>
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
                <Button>Xem Audit Log</Button>
              </div>
            </Card>
          </div>
        )}

        {/* Sessions Tab */}
        {activeTab === 'sessions' && (
          <div className="space-y-6">
            <Card title="Phiên đăng nhập hiện tại">
              <div className="space-y-4">
                <div className="flex items-center justify-between p-4 bg-green-50 rounded-lg">
                  <div className="flex items-center space-x-3">
                    <div className="w-10 h-10 bg-green-100 rounded-full flex items-center justify-center">
                      <svg className="w-6 h-6 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
                      </svg>
                    </div>
                    <div>
                      <h4 className="font-medium text-gray-900">Windows • Chrome</h4>
                      <p className="text-sm text-gray-600">IP: 192.168.1.100</p>
                      <p className="text-xs text-gray-500">Hoạt động hiện tại</p>
                    </div>
                  </div>
                  <span className="px-3 py-1 bg-green-100 text-green-800 text-xs font-medium rounded-full">
                    Hiện tại
                  </span>
                </div>
              </div>
            </Card>

            <Card title="Phiên khác">
              <div className="space-y-3">
                <p className="text-sm text-gray-600 mb-4">Quản lý các phiên đăng nhập khác trên thiết bị khác</p>
                
                <div className="flex items-center justify-between p-4 bg-gray-50 rounded-lg">
                  <div className="flex items-center space-x-3">
                    <div className="w-10 h-10 bg-gray-100 rounded-full flex items-center justify-center">
                      <svg className="w-6 h-6 text-gray-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 18h.01M8 21h8a2 2 0 002-2V5a2 2 0 00-2-2H8a2 2 0 00-2 2v14a2 2 0 002 2z" />
                      </svg>
                    </div>
                    <div>
                      <h4 className="font-medium text-gray-900">iPhone • Safari</h4>
                      <p className="text-sm text-gray-600">IP: 192.168.1.101</p>
                      <p className="text-xs text-gray-500">Hoạt động 2 giờ trước</p>
                    </div>
                  </div>
                  <Button variant="danger" size="sm">Đăng xuất</Button>
                </div>

                <div className="flex items-center justify-between p-4 bg-gray-50 rounded-lg">
                  <div className="flex items-center space-x-3">
                    <div className="w-10 h-10 bg-gray-100 rounded-full flex items-center justify-center">
                      <svg className="w-6 h-6 text-gray-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 18h.01M7 21h10a2 2 0 002-2V5a2 2 0 00-2-2H7a2 2 0 00-2 2v14a2 2 0 002 2z" />
                      </svg>
                    </div>
                    <div>
                      <h4 className="font-medium text-gray-900">Android • Chrome</h4>
                      <p className="text-sm text-gray-600">IP: 192.168.1.102</p>
                      <p className="text-xs text-gray-500">Hoạt động 1 ngày trước</p>
                    </div>
                  </div>
                  <Button variant="danger" size="sm">Đăng xuất</Button>
                </div>
              </div>

              <div className="mt-4 pt-4 border-t">
                <Button variant="danger" fullWidth>
                  Đăng xuất tất cả phiên khác
                </Button>
              </div>
            </Card>
          </div>
        )}
      </div>
    </div>
  );
};

export default SettingsPage;
