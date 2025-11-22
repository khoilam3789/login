import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import { useVault } from '../contexts/VaultContext';
import { VaultItem } from '../services/vault.service';
import Button from '../components/Button';
import Card from '../components/Card';
import Modal from '../components/Modal';
import Input from '../components/Input';
import ClientCryptoService from '../services/crypto.service';
import toast from 'react-hot-toast';

const VaultPage: React.FC = () => {
  const navigate = useNavigate();
  const { user, logout } = useAuth();
  const { items, isLoading, createVaultItem, updateVaultItem, deleteVaultItem } = useVault();
  
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedCategory, setSelectedCategory] = useState<string>('all');
  const [showModal, setShowModal] = useState(false);
  const [editingItem, setEditingItem] = useState<VaultItem | null>(null);
  const [formData, setFormData] = useState({
    title: '',
    username: '',
    password: '',
    url: '',
    notes: '',
    category: 'login' as VaultItem['category'],
    favorite: false,
    tags: [] as string[]
  });

  const filteredItems = items.filter(item => {
    const matchesSearch = 
      item.title?.toLowerCase().includes(searchQuery.toLowerCase()) ||
      item.username?.toLowerCase().includes(searchQuery.toLowerCase()) ||
      item.url?.toLowerCase().includes(searchQuery.toLowerCase());
    
    const matchesCategory = selectedCategory === 'all' || item.category === selectedCategory;
    
    return matchesSearch && matchesCategory;
  });

  const handleOpenModal = (item?: VaultItem) => {
    if (item) {
      setEditingItem(item);
      setFormData({
        title: item.title,
        username: item.username,
        password: item.password,
        url: item.url || '',
        notes: item.notes || '',
        category: item.category,
        favorite: item.favorite,
        tags: item.tags
      });
    } else {
      setEditingItem(null);
      setFormData({
        title: '',
        username: '',
        password: '',
        url: '',
        notes: '',
        category: 'login',
        favorite: false,
        tags: []
      });
    }
    setShowModal(true);
  };

  const handleCloseModal = () => {
    setShowModal(false);
    setEditingItem(null);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    try {
      if (editingItem) {
        await updateVaultItem(editingItem.id, formData);
        toast.success('Cập nhật thành công!');
      } else {
        await createVaultItem(formData);
        toast.success('Tạo mục mới thành công!');
      }
      handleCloseModal();
    } catch (error: any) {
      toast.error(error.message || 'Có lỗi xảy ra');
    }
  };

  const handleDelete = async (id: string) => {
    if (confirm('Bạn có chắc muốn xóa mục này?')) {
      try {
        await deleteVaultItem(id);
        toast.success('Xóa thành công!');
      } catch (error: any) {
        toast.error(error.message || 'Không thể xóa');
      }
    }
  };

  const handleCopyToClipboard = async (text: string, label: string) => {
    try {
      await navigator.clipboard.writeText(text);
      toast.success(`Đã sao chép ${label}!`);
    } catch (error) {
      toast.error('Không thể sao chép');
    }
  };

  const handleGeneratePassword = () => {
    const password = ClientCryptoService.generatePassword(16);
    setFormData({ ...formData, password });
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
              <h1 className="text-xl font-bold text-gray-900">Vault</h1>
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

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Header Actions */}
        <div className="flex flex-col md:flex-row justify-between items-start md:items-center mb-6 space-y-4 md:space-y-0">
          <div className="flex-1 max-w-md">
            <Input
              type="text"
              placeholder="Tìm kiếm..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              icon={
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                </svg>
              }
            />
          </div>
          <Button onClick={() => handleOpenModal()}>
            + Thêm mới
          </Button>
        </div>

        {/* Vault Items */}
        {isLoading ? (
          <div className="flex justify-center py-12">
            <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
          </div>
        ) : filteredItems.length === 0 ? (
          <Card>
            <div className="text-center py-12">
              <svg className="mx-auto h-24 w-24 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M20 13V6a2 2 0 00-2-2H6a2 2 0 00-2 2v7m16 0v5a2 2 0 01-2 2H6a2 2 0 01-2-2v-5m16 0h-2.586a1 1 0 00-.707.293l-2.414 2.414a1 1 0 01-.707.293h-3.172a1 1 0 01-.707-.293l-2.414-2.414A1 1 0 006.586 13H4" />
              </svg>
              <h3 className="mt-4 text-lg font-medium text-gray-900">Không tìm thấy mục nào</h3>
              <p className="mt-2 text-sm text-gray-600">
                {searchQuery ? 'Thử tìm kiếm với từ khóa khác' : 'Bắt đầu thêm mục vào vault'}
              </p>
            </div>
          </Card>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {filteredItems.map((item) => (
              <Card key={item.id} className="hover:shadow-lg transition-shadow">
                <div className="space-y-3">
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <h3 className="font-semibold text-gray-900">
                        {item.title}
                      </h3>
                      <p className="text-sm text-gray-600">{item.username}</p>
                      {item.url && (
                        <a
                          href={item.url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-xs text-blue-600 hover:underline"
                        >
                          {item.url}
                        </a>
                      )}
                    </div>
                  </div>

                  <div className="flex items-center space-x-2">
                    <input
                      type="password"
                      value={item.password}
                      readOnly
                      className="flex-1 text-sm px-3 py-1 border rounded bg-gray-50"
                    />
                    <button
                      onClick={() => handleCopyToClipboard(item.password, 'mật khẩu')}
                      className="p-1 text-gray-600 hover:text-blue-600"
                    >
                      <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                      </svg>
                    </button>
                  </div>

                  {item.tags.length > 0 && (
                    <div className="flex flex-wrap gap-1">
                      {item.tags.map((tag, index) => (
                        <span key={index} className="px-2 py-1 bg-gray-100 text-xs text-gray-600 rounded">
                          {tag}
                        </span>
                      ))}
                    </div>
                  )}

                  <div className="flex space-x-2 pt-2 border-t">
                    <Button variant="secondary" size="sm" onClick={() => handleOpenModal(item)}>
                      Sửa
                    </Button>
                    <Button variant="danger" size="sm" onClick={() => handleDelete(item.id)}>
                      Xóa
                    </Button>
                  </div>
                </div>
              </Card>
            ))}
          </div>
        )}
      </div>

      {/* Add/Edit Modal */}
      <Modal isOpen={showModal} onClose={handleCloseModal} title={editingItem ? 'Chỉnh sửa mục' : 'Thêm mục mới'} size="lg">
        <form onSubmit={handleSubmit} className="space-y-4">
          <Input
            label="Tiêu đề *"
            value={formData.title}
            onChange={(e) => setFormData({ ...formData, title: e.target.value })}
            required
          />

          <Input
            label="Tên đăng nhập / Email"
            value={formData.username}
            onChange={(e) => setFormData({ ...formData, username: e.target.value })}
          />

          <div>
            <Input
              label="Mật khẩu"
              type="password"
              value={formData.password}
              onChange={(e) => setFormData({ ...formData, password: e.target.value })}
            />
            <Button type="button" variant="secondary" size="sm" onClick={handleGeneratePassword} className="mt-2">
              🎲 Tạo mật khẩu ngẫu nhiên
            </Button>
          </div>

          <Input
            label="URL"
            type="url"
            value={formData.url}
            onChange={(e) => setFormData({ ...formData, url: e.target.value })}
            placeholder="https://example.com"
          />

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Ghi chú</label>
            <textarea
              value={formData.notes}
              onChange={(e) => setFormData({ ...formData, notes: e.target.value })}
              rows={3}
              className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>

          <div className="flex space-x-2 pt-4">
            <Button type="submit" fullWidth>
              {editingItem ? 'Cập nhật' : 'Tạo mới'}
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

export default VaultPage;
