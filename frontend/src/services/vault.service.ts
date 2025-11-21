import apiClient from './api.service';
import ClientCryptoService, { EncryptedData } from './crypto.service';

export interface VaultItem {
  id: string;
  title: string;
  username: string;
  password: string;
  url?: string;
  notes?: string;
  category: 'login' | 'card' | 'note' | 'identity';
  favorite: boolean;
  tags: string[];
  customFields?: Array<{
    label: string;
    value: string;
    type: 'text' | 'password' | 'email' | 'url';
  }>;
  createdAt: string;
  updatedAt: string;
}

export interface EncryptedVaultItem {
  id: string;
  encryptedData: string;
  dataIV: string;
  category: string;
  favorite: boolean;
  tags: string[];
  createdAt: string;
  updatedAt: string;
}

export class VaultService {
  /**
   * Get all vault items
   */
  static async getVaultItems(dek: CryptoKey): Promise<VaultItem[]> {
    try {
      const response = await apiClient.get('/vault');
      const encryptedItems = response.data.data || []; // Backend returns { success, data }

      const items = await Promise.all(
        encryptedItems.map(async (item: any) => {
          // Item in list doesn't have encryptedData, need to fetch full item
          const fullItem = await this.getVaultItem(item._id, dek);
          return fullItem;
        })
      );

      return items;
    } catch (error: any) {
      console.error('Get vault items error:', error);
      throw new Error(error.response?.data?.message || 'Không thể tải dữ liệu');
    }
  }

  /**
   * Get vault item by ID
   */
  static async getVaultItem(id: string, dek: CryptoKey): Promise<VaultItem> {
    try {
      const response = await apiClient.get(`/vault/${id}`);
      const item = response.data.data; // Backend returns { success, data }

      const decrypted = await ClientCryptoService.decryptObject<any>(
        {
          ciphertext: item.encryptedData,
          iv: item.iv
        },
        dek
      );

      return {
        ...decrypted,
        id: item._id,
        category: item.type as VaultItem['category'], // Backend uses 'type' field
        favorite: item.favorite,
        tags: item.tags || [],
        createdAt: item.createdAt,
        updatedAt: item.updatedAt
      };
    } catch (error: any) {
      console.error('Get vault item error:', error);
      throw new Error(error.response?.data?.message || 'Không tìm thấy mục');
    }
  }

  /**
   * Create vault item
   */
  static async createVaultItem(
    item: Omit<VaultItem, 'id' | 'createdAt' | 'updatedAt'>,
    dek: CryptoKey
  ): Promise<VaultItem> {
    try {
      const dataToEncrypt = {
        title: item.title,
        username: item.username,
        password: item.password,
        url: item.url,
        notes: item.notes,
        customFields: item.customFields
      };

      const encrypted = await ClientCryptoService.encryptObject(dataToEncrypt, dek);

      const response = await apiClient.post('/vault', {
        name: item.title, // Backend expects 'name' field
        type: item.category === 'login' ? 'password' : item.category, // Backend uses 'type' not 'category'
        encryptedData: encrypted.ciphertext,
        iv: encrypted.iv, // Backend expects 'iv' not 'dataIV'
        category: item.category,
        favorite: item.favorite || false,
        tags: item.tags || []
      });

      return this.getVaultItem(response.data.data._id, dek);
    } catch (error: any) {
      console.error('Create vault item error:', error);
      throw new Error(error.response?.data?.message || 'Không thể tạo mục');
    }
  }

  /**
   * Update vault item
   */
  static async updateVaultItem(
    id: string,
    item: Partial<Omit<VaultItem, 'id' | 'createdAt' | 'updatedAt'>>,
    dek: CryptoKey
  ): Promise<VaultItem> {
    try {
      const dataToEncrypt = {
        title: item.title,
        username: item.username,
        password: item.password,
        url: item.url,
        notes: item.notes,
        customFields: item.customFields
      };

      const encrypted = await ClientCryptoService.encryptObject(dataToEncrypt, dek);

      const response = await apiClient.put(`/vault/${id}`, {
        name: item.title,
        encryptedData: encrypted.ciphertext,
        iv: encrypted.iv,
        category: item.category,
        favorite: item.favorite,
        tags: item.tags
      });

      return this.getVaultItem(response.data.data._id, dek);
    } catch (error: any) {
      console.error('Update vault item error:', error);
      throw new Error(error.response?.data?.message || 'Không thể cập nhật');
    }
  }

  /**
   * Delete vault item
   */
  static async deleteVaultItem(id: string): Promise<void> {
    try {
      await apiClient.delete(`/vault/${id}`);
    } catch (error: any) {
      throw new Error(error.response?.data?.message || 'Không thể xóa mục');
    }
  }

  /**
   * Search vault items
   */
  static async searchVaultItems(
    query: string,
    dek: CryptoKey
  ): Promise<VaultItem[]> {
    const items = await this.getVaultItems(dek);
    
    const lowerQuery = query.toLowerCase();
    return items.filter(item => 
      item.title.toLowerCase().includes(lowerQuery) ||
      item.username.toLowerCase().includes(lowerQuery) ||
      item.url?.toLowerCase().includes(lowerQuery) ||
      item.notes?.toLowerCase().includes(lowerQuery) ||
      item.tags.some(tag => tag.toLowerCase().includes(lowerQuery))
    );
  }

  /**
   * Toggle favorite
   */
  static async toggleFavorite(id: string, dek: CryptoKey): Promise<VaultItem> {
    try {
      const item = await this.getVaultItem(id, dek);
      return await this.updateVaultItem(
        id,
        { favorite: !item.favorite },
        dek
      );
    } catch (error: any) {
      throw new Error(error.response?.data?.message || 'Không thể cập nhật');
    }
  }

  /**
   * Check password strength and reuse
   */
  static async analyzePasswordSecurity(
    password: string,
    dek: CryptoKey
  ): Promise<{
    strength: ReturnType<typeof ClientCryptoService.calculatePasswordStrength>;
    isReused: boolean;
    timesUsed: number;
  }> {
    const strength = ClientCryptoService.calculatePasswordStrength(password);
    const items = await this.getVaultItems(dek);
    
    const timesUsed = items.filter(item => item.password === password).length;
    
    return {
      strength,
      isReused: timesUsed > 1,
      timesUsed
    };
  }
}

export default VaultService;
