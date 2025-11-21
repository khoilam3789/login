import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { VaultService, VaultItem } from '../services/vault.service';
import { useAuth } from './AuthContext';

interface VaultContextType {
  items: VaultItem[];
  isLoading: boolean;
  error: string | null;
  loadVaultItems: () => Promise<void>;
  getVaultItem: (id: string) => Promise<VaultItem | null>;
  createVaultItem: (item: Omit<VaultItem, 'id' | 'createdAt' | 'updatedAt'>) => Promise<VaultItem>;
  updateVaultItem: (id: string, item: Partial<Omit<VaultItem, 'id' | 'createdAt' | 'updatedAt'>>) => Promise<VaultItem>;
  deleteVaultItem: (id: string) => Promise<void>;
  searchVaultItems: (query: string) => Promise<VaultItem[]>;
  toggleFavorite: (id: string) => Promise<void>;
}

const VaultContext = createContext<VaultContextType | undefined>(undefined);

export const useVault = () => {
  const context = useContext(VaultContext);
  if (!context) {
    throw new Error('useVault must be used within VaultProvider');
  }
  return context;
};

interface VaultProviderProps {
  children: ReactNode;
}

export const VaultProvider: React.FC<VaultProviderProps> = ({ children }) => {
  const { dek, isAuthenticated } = useAuth();
  const [items, setItems] = useState<VaultItem[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (isAuthenticated && dek) {
      loadVaultItems();
    } else {
      setItems([]);
    }
  }, [isAuthenticated, dek]);

  const loadVaultItems = async () => {
    if (!dek) {
      setError('DEK không khả dụng');
      return;
    }

    try {
      setIsLoading(true);
      setError(null);
      const vaultItems = await VaultService.getVaultItems(dek);
      setItems(vaultItems);
    } catch (err: any) {
      setError(err.message || 'Không thể tải dữ liệu vault');
      console.error('Load vault items error:', err);
    } finally {
      setIsLoading(false);
    }
  };

  const getVaultItem = async (id: string): Promise<VaultItem | null> => {
    if (!dek) {
      throw new Error('DEK không khả dụng');
    }

    try {
      const item = await VaultService.getVaultItem(id, dek);
      return item;
    } catch (err: any) {
      setError(err.message || 'Không tìm thấy mục');
      return null;
    }
  };

  const createVaultItem = async (
    item: Omit<VaultItem, 'id' | 'createdAt' | 'updatedAt'>
  ): Promise<VaultItem> => {
    if (!dek) {
      throw new Error('DEK không khả dụng');
    }

    try {
      setIsLoading(true);
      setError(null);
      const newItem = await VaultService.createVaultItem(item, dek);
      setItems(prev => [...prev, newItem]);
      return newItem;
    } catch (err: any) {
      setError(err.message || 'Không thể tạo mục');
      throw err;
    } finally {
      setIsLoading(false);
    }
  };

  const updateVaultItem = async (
    id: string,
    item: Partial<Omit<VaultItem, 'id' | 'createdAt' | 'updatedAt'>>
  ): Promise<VaultItem> => {
    if (!dek) {
      throw new Error('DEK không khả dụng');
    }

    try {
      setIsLoading(true);
      setError(null);
      const updatedItem = await VaultService.updateVaultItem(id, item, dek);
      setItems(prev => prev.map(i => (i.id === id ? updatedItem : i)));
      return updatedItem;
    } catch (err: any) {
      setError(err.message || 'Không thể cập nhật mục');
      throw err;
    } finally {
      setIsLoading(false);
    }
  };

  const deleteVaultItem = async (id: string): Promise<void> => {
    try {
      setIsLoading(true);
      setError(null);
      await VaultService.deleteVaultItem(id);
      setItems(prev => prev.filter(i => i.id !== id));
    } catch (err: any) {
      setError(err.message || 'Không thể xóa mục');
      throw err;
    } finally {
      setIsLoading(false);
    }
  };

  const searchVaultItems = async (query: string): Promise<VaultItem[]> => {
    if (!dek) {
      throw new Error('DEK không khả dụng');
    }

    try {
      const results = await VaultService.searchVaultItems(query, dek);
      return results;
    } catch (err: any) {
      setError(err.message || 'Tìm kiếm thất bại');
      return [];
    }
  };

  const toggleFavorite = async (id: string): Promise<void> => {
    if (!dek) {
      throw new Error('DEK không khả dụng');
    }

    try {
      setIsLoading(true);
      setError(null);
      const updatedItem = await VaultService.toggleFavorite(id, dek);
      setItems(prev => prev.map(i => (i.id === id ? updatedItem : i)));
    } catch (err: any) {
      setError(err.message || 'Không thể cập nhật');
      throw err;
    } finally {
      setIsLoading(false);
    }
  };

  const value: VaultContextType = {
    items,
    isLoading,
    error,
    loadVaultItems,
    getVaultItem,
    createVaultItem,
    updateVaultItem,
    deleteVaultItem,
    searchVaultItems,
    toggleFavorite
  };

  return <VaultContext.Provider value={value}>{children}</VaultContext.Provider>;
};

export default VaultContext;
