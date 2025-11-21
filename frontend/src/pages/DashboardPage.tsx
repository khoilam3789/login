import React from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import { useVault } from '../contexts/VaultContext';
import Button from '../components/Button';
import Card from '../components/Card';

const DashboardPage: React.FC = () => {
  const navigate = useNavigate();
  const { user, logout } = useAuth();
  const { items } = useVault();

  const handleLogout = async () => {
    await logout();
    navigate('/login');
  };

  const stats = {
    total: items.length,
    favorites: items.filter(i => i.favorite).length,
    logins: items.filter(i => i.category === 'login').length,
    cards: items.filter(i => i.category === 'card').length,
    notes: items.filter(i => i.category === 'note').length
  };

  return (
    <div className="min-h-screen bg-gray-50">
      <nav className="bg-white shadow-sm">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center h-16">
            <div className="flex items-center">
              <h1 className="text-xl font-bold text-gray-900">Password Manager</h1>
            </div>
            <div className="flex items-center space-x-4">
              <span className="text-sm text-gray-600">{user?.email}</span>
              <Button variant="ghost" size="sm" onClick={handleLogout}>
                Đăng xuất
              </Button>
            </div>
          </div>
        </div>
      </nav>

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="mb-8">
          <h2 className="text-3xl font-bold text-gray-900 mb-2">Dashboard</h2>
          <p className="text-gray-600">Chào mừng trở lại! Quản lý vault của bạn.</p>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-5 gap-4 mb-8">
          <Card className="text-center">
            <div className="text-3xl font-bold text-blue-600 mb-2">{stats.total}</div>
            <div className="text-sm text-gray-600">Tổng số mục</div>
          </Card>
          <Card className="text-center">
            <div className="text-3xl font-bold text-yellow-600 mb-2">{stats.favorites}</div>
            <div className="text-sm text-gray-600">Yêu thích</div>
          </Card>
          <Card className="text-center">
            <div className="text-3xl font-bold text-green-600 mb-2">{stats.logins}</div>
            <div className="text-sm text-gray-600">Đăng nhập</div>
          </Card>
          <Card className="text-center">
            <div className="text-3xl font-bold text-purple-600 mb-2">{stats.cards}</div>
            <div className="text-sm text-gray-600">Thẻ</div>
          </Card>
          <Card className="text-center">
            <div className="text-3xl font-bold text-gray-600 mb-2">{stats.notes}</div>
            <div className="text-sm text-gray-600">Ghi chú</div>
          </Card>
        </div>

        {/* Quick Actions */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          <Card
            title="Vault"
            subtitle="Quản lý mật khẩu và dữ liệu"
            className="cursor-pointer hover:shadow-xl"
            onClick={() => navigate('/vault')}
          >
            <div className="flex items-center justify-center h-24">
              <svg className="w-16 h-16 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
              </svg>
            </div>
          </Card>

          <Card
            title="OTP Bên ngoài"
            subtitle="Quản lý 2FA từ dịch vụ khác"
            className="cursor-pointer hover:shadow-xl"
            onClick={() => navigate('/external-otp')}
          >
            <div className="flex items-center justify-center h-24">
              <svg className="w-16 h-16 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 11c0 3.517-1.009 6.799-2.753 9.571m-3.44-2.04l.054-.09A13.916 13.916 0 008 11a4 4 0 118 0c0 1.017-.07 2.019-.203 3m-2.118 6.844A21.88 21.88 0 0015.171 17m3.839 1.132c.645-2.266.99-4.659.99-7.132A8 8 0 008 4.07M3 15.364c.64-1.319 1-2.8 1-4.364 0-1.457.39-2.823 1.07-4" />
              </svg>
            </div>
          </Card>

          <Card
            title="Cài đặt"
            subtitle="Tùy chỉnh và bảo mật"
            className="cursor-pointer hover:shadow-xl"
            onClick={() => navigate('/settings')}
          >
            <div className="flex items-center justify-center h-24">
              <svg className="w-16 h-16 text-purple-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
              </svg>
            </div>
          </Card>

          <Card
            title="Bảo mật"
            subtitle="Kiểm tra độ an toàn"
            className="cursor-pointer hover:shadow-xl"
          >
            <div className="flex items-center justify-center h-24">
              <svg className="w-16 h-16 text-red-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
              </svg>
            </div>
          </Card>
        </div>

        {/* Recent Activity */}
        {items.length > 0 && (
          <div className="mt-8">
            <Card title="Mục gần đây" subtitle="Các mục được cập nhật gần nhất">
              <div className="space-y-3">
                {items
                  .sort((a, b) => new Date(b.updatedAt).getTime() - new Date(a.updatedAt).getTime())
                  .slice(0, 5)
                  .map((item) => (
                    <div
                      key={item.id}
                      className="flex items-center justify-between p-3 bg-gray-50 rounded-lg hover:bg-gray-100 cursor-pointer"
                      onClick={() => navigate('/vault')}
                    >
                      <div className="flex items-center space-x-3">
                        <div className="w-10 h-10 bg-blue-100 rounded-full flex items-center justify-center">
                          <svg className="w-5 h-5 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                          </svg>
                        </div>
                        <div>
                          <div className="font-medium text-gray-900">{item.title}</div>
                          <div className="text-sm text-gray-500">{item.username}</div>
                        </div>
                      </div>
                      <div className="text-sm text-gray-500">
                        {new Date(item.updatedAt).toLocaleDateString('vi-VN')}
                      </div>
                    </div>
                  ))}
              </div>
            </Card>
          </div>
        )}

        {/* Empty State */}
        {items.length === 0 && (
          <div className="mt-8">
            <Card>
              <div className="text-center py-12">
                <svg className="mx-auto h-24 w-24 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                </svg>
                <h3 className="mt-4 text-lg font-medium text-gray-900">Vault trống</h3>
                <p className="mt-2 text-sm text-gray-600">
                  Bắt đầu thêm mật khẩu và dữ liệu vào vault của bạn
                </p>
                <div className="mt-6">
                  <Button onClick={() => navigate('/vault')}>
                    Đi đến Vault
                  </Button>
                </div>
              </div>
            </Card>
          </div>
        )}
      </div>
    </div>
  );
};

export default DashboardPage;
