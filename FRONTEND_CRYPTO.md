# Client-Side Encryption Implementation (React + TypeScript)

## 1. CRYPTO SERVICE (Frontend)

```typescript
// src/services/crypto.service.ts

/**
 * Client-side Cryptography Service
 * Implements Zero-Knowledge encryption using Web Crypto API
 */

export interface DerivedKeys {
  encryptionKey: CryptoKey;
  authKey: string;
}

export interface EncryptedData {
  ciphertext: string;
  iv: string;
}

export class ClientCryptoService {
  private static readonly PBKDF2_ITERATIONS = 600000;
  private static readonly PBKDF2_AUTH_ITERATIONS = 100000;
  private static readonly KEY_SIZE = 256;
  private static readonly SALT_SIZE = 32;
  private static readonly IV_SIZE = 12;

  /**
   * Generate random salt for key derivation
   */
  static generateSalt(): string {
    const salt = crypto.getRandomValues(new Uint8Array(this.SALT_SIZE));
    return this.arrayBufferToBase64(salt);
  }

  /**
   * Derive encryption key and auth key from master password
   */
  static async deriveMasterKeys(
    masterPassword: string,
    salt: string
  ): Promise<DerivedKeys> {
    const encoder = new TextEncoder();
    const saltBuffer = this.base64ToArrayBuffer(salt);

    // Import master password as key material
    const passwordKey = await crypto.subtle.importKey(
      'raw',
      encoder.encode(masterPassword),
      'PBKDF2',
      false,
      ['deriveBits', 'deriveKey']
    );

    // Derive Encryption Key (EK)
    const encryptionKey = await crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: saltBuffer,
        iterations: this.PBKDF2_ITERATIONS,
        hash: 'SHA-256'
      },
      passwordKey,
      {
        name: 'AES-GCM',
        length: this.KEY_SIZE
      },
      true, // extractable (needed for further derivation)
      ['encrypt', 'decrypt']
    );

    // Export EK to derive Auth Key
    const ekRaw = await crypto.subtle.exportKey('raw', encryptionKey);
    
    // Derive Auth Key from EK
    const authSalt = encoder.encode('auth');
    const authKeyMaterial = await crypto.subtle.importKey(
      'raw',
      ekRaw,
      'PBKDF2',
      false,
      ['deriveBits']
    );

    const authKeyBits = await crypto.subtle.deriveBits(
      {
        name: 'PBKDF2',
        salt: authSalt,
        iterations: this.PBKDF2_AUTH_ITERATIONS,
        hash: 'SHA-256'
      },
      authKeyMaterial,
      this.KEY_SIZE
    );

    // Import EK back as non-extractable for security
    const finalEncryptionKey = await crypto.subtle.importKey(
      'raw',
      ekRaw,
      {
        name: 'AES-GCM',
        length: this.KEY_SIZE
      },
      false, // non-extractable
      ['encrypt', 'decrypt']
    );

    return {
      encryptionKey: finalEncryptionKey,
      authKey: this.arrayBufferToBase64(authKeyBits)
    };
  }

  /**
   * Hash auth key with SHA-256 (before sending to server)
   * Server will hash again with Argon2
   */
  static async hashAuthKey(authKey: string): Promise<string> {
    const encoder = new TextEncoder();
    const data = encoder.encode(authKey);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    return this.arrayBufferToHex(hashBuffer);
  }

  /**
   * Generate Data Encryption Key (DEK)
   */
  static async generateDEK(): Promise<CryptoKey> {
    return await crypto.subtle.generateKey(
      {
        name: 'AES-GCM',
        length: this.KEY_SIZE
      },
      true, // extractable (to encrypt with EK)
      ['encrypt', 'decrypt']
    );
  }

  /**
   * Encrypt DEK with Encryption Key
   */
  static async encryptDEK(
    dek: CryptoKey,
    encryptionKey: CryptoKey
  ): Promise<EncryptedData> {
    // Export DEK
    const dekRaw = await crypto.subtle.exportKey('raw', dek);
    
    // Encrypt with EK
    const iv = crypto.getRandomValues(new Uint8Array(this.IV_SIZE));
    
    const encryptedDEK = await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: iv,
        tagLength: 128
      },
      encryptionKey,
      dekRaw
    );

    return {
      ciphertext: this.arrayBufferToBase64(encryptedDEK),
      iv: this.arrayBufferToBase64(iv)
    };
  }

  /**
   * Decrypt DEK with Encryption Key
   */
  static async decryptDEK(
    encryptedData: EncryptedData,
    encryptionKey: CryptoKey
  ): Promise<CryptoKey> {
    const ciphertext = this.base64ToArrayBuffer(encryptedData.ciphertext);
    const iv = this.base64ToArrayBuffer(encryptedData.iv);

    const dekRaw = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: iv,
        tagLength: 128
      },
      encryptionKey,
      ciphertext
    );

    // Import as CryptoKey
    return await crypto.subtle.importKey(
      'raw',
      dekRaw,
      {
        name: 'AES-GCM',
        length: this.KEY_SIZE
      },
      false, // non-extractable for security
      ['encrypt', 'decrypt']
    );
  }

  /**
   * Encrypt data with DEK
   */
  static async encrypt(
    plaintext: string,
    dek: CryptoKey
  ): Promise<EncryptedData> {
    const encoder = new TextEncoder();
    const data = encoder.encode(plaintext);
    const iv = crypto.getRandomValues(new Uint8Array(this.IV_SIZE));

    const ciphertext = await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: iv,
        tagLength: 128
      },
      dek,
      data
    );

    return {
      ciphertext: this.arrayBufferToBase64(ciphertext),
      iv: this.arrayBufferToBase64(iv)
    };
  }

  /**
   * Decrypt data with DEK
   */
  static async decrypt(
    encryptedData: EncryptedData,
    dek: CryptoKey
  ): Promise<string> {
    const ciphertext = this.base64ToArrayBuffer(encryptedData.ciphertext);
    const iv = this.base64ToArrayBuffer(encryptedData.iv);

    const decrypted = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: iv,
        tagLength: 128
      },
      dek,
      ciphertext
    );

    const decoder = new TextDecoder();
    return decoder.decode(decrypted);
  }

  /**
   * Encrypt object (convert to JSON first)
   */
  static async encryptObject(
    obj: any,
    dek: CryptoKey
  ): Promise<EncryptedData> {
    const json = JSON.stringify(obj);
    return await this.encrypt(json, dek);
  }

  /**
   * Decrypt to object
   */
  static async decryptObject<T>(
    encryptedData: EncryptedData,
    dek: CryptoKey
  ): Promise<T> {
    const json = await this.decrypt(encryptedData, dek);
    return JSON.parse(json) as T;
  }

  /**
   * Utility: ArrayBuffer to Base64
   */
  private static arrayBufferToBase64(buffer: ArrayBuffer): string {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }

  /**
   * Utility: Base64 to ArrayBuffer
   */
  private static base64ToArrayBuffer(base64: string): ArrayBuffer {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }

  /**
   * Utility: ArrayBuffer to Hex
   */
  private static arrayBufferToHex(buffer: ArrayBuffer): string {
    const bytes = new Uint8Array(buffer);
    return Array.from(bytes)
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  }

  /**
   * Generate secure random password
   */
  static generatePassword(length: number = 16): string {
    const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>?';
    const randomValues = crypto.getRandomValues(new Uint32Array(length));
    
    let password = '';
    for (let i = 0; i < length; i++) {
      password += charset[randomValues[i] % charset.length];
    }
    
    return password;
  }

  /**
   * Calculate password strength
   */
  static calculatePasswordStrength(password: string): {
    score: number;
    label: 'weak' | 'medium' | 'strong' | 'very_strong';
    feedback: string[];
  } {
    let score = 0;
    const feedback: string[] = [];

    // Length
    if (password.length >= 8) score += 1;
    if (password.length >= 12) score += 1;
    if (password.length >= 16) score += 1;
    else feedback.push('Use at least 16 characters');

    // Character variety
    if (/[a-z]/.test(password)) score += 1;
    else feedback.push('Add lowercase letters');
    
    if (/[A-Z]/.test(password)) score += 1;
    else feedback.push('Add uppercase letters');
    
    if (/\d/.test(password)) score += 1;
    else feedback.push('Add numbers');
    
    if (/[^A-Za-z0-9]/.test(password)) score += 1;
    else feedback.push('Add special characters');

    // Common patterns (weak)
    const commonPatterns = ['123', 'abc', 'password', 'qwerty'];
    if (commonPatterns.some(p => password.toLowerCase().includes(p))) {
      score -= 2;
      feedback.push('Avoid common patterns');
    }

    let label: 'weak' | 'medium' | 'strong' | 'very_strong';
    if (score <= 3) label = 'weak';
    else if (score <= 5) label = 'medium';
    else if (score <= 6) label = 'strong';
    else label = 'very_strong';

    return { score, label, feedback };
  }
}

export default ClientCryptoService;
```

## 2. AUTHENTICATION SERVICE (Frontend)

```typescript
// src/services/auth.service.ts

import axios from 'axios';
import ClientCryptoService from './crypto.service';

const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:5000/api/v1';

export interface RegisterData {
  email: string;
  masterPassword: string;
}

export interface LoginData {
  email: string;
  masterPassword: string;
}

export interface AuthResponse {
  success: boolean;
  token: string;
  refreshToken: string;
  user: {
    id: string;
    email: string;
  };
  encryptedDEK: string;
  dekIV: string;
}

export class AuthService {
  /**
   * Register new user
   */
  static async register(data: RegisterData): Promise<AuthResponse> {
    try {
      // 1. Generate salt
      const salt = ClientCryptoService.generateSalt();

      // 2. Derive keys from master password
      const { encryptionKey, authKey } = await ClientCryptoService.deriveMasterKeys(
        data.masterPassword,
        salt
      );

      // 3. Hash auth key for server
      const authKeyHash = await ClientCryptoService.hashAuthKey(authKey);

      // 4. Generate DEK
      const dek = await ClientCryptoService.generateDEK();

      // 5. Encrypt DEK with encryption key
      const encryptedDEK = await ClientCryptoService.encryptDEK(dek, encryptionKey);

      // 6. Send to server
      const response = await axios.post(`${API_URL}/auth/register`, {
        email: data.email,
        authKeyHash,
        salt,
        encryptedDEK: encryptedDEK.ciphertext,
        dekIV: encryptedDEK.iv
      });

      return response.data;
    } catch (error: any) {
      throw new Error(error.response?.data?.message || 'Registration failed');
    }
  }

  /**
   * Login user
   */
  static async login(data: LoginData): Promise<{
    authResponse: AuthResponse;
    dek: CryptoKey;
  }> {
    try {
      // 1. Get salt from server
      const saltResponse = await axios.post(`${API_URL}/auth/get-salt`, {
        email: data.email
      });
      const salt = saltResponse.data.salt;

      // 2. Derive keys
      const { encryptionKey, authKey } = await ClientCryptoService.deriveMasterKeys(
        data.masterPassword,
        salt
      );

      // 3. Hash auth key
      const authKeyHash = await ClientCryptoService.hashAuthKey(authKey);

      // 4. Login
      const response = await axios.post(`${API_URL}/auth/login`, {
        email: data.email,
        authKeyHash
      });

      const authResponse: AuthResponse = response.data;

      // 5. Decrypt DEK
      const dek = await ClientCryptoService.decryptDEK(
        {
          ciphertext: authResponse.encryptedDEK,
          iv: authResponse.dekIV
        },
        encryptionKey
      );

      // 6. Store tokens
      localStorage.setItem('token', authResponse.token);
      localStorage.setItem('refreshToken', authResponse.refreshToken);

      return { authResponse, dek };
    } catch (error: any) {
      throw new Error(error.response?.data?.message || 'Login failed');
    }
  }

  /**
   * Logout
   */
  static async logout(): Promise<void> {
    try {
      const token = localStorage.getItem('token');
      if (token) {
        await axios.post(
          `${API_URL}/auth/logout`,
          {},
          {
            headers: { Authorization: `Bearer ${token}` }
          }
        );
      }
    } catch (error) {
      // Ignore errors during logout
    } finally {
      localStorage.removeItem('token');
      localStorage.removeItem('refreshToken');
      // Clear DEK from memory (handled by context)
    }
  }

  /**
   * Refresh access token
   */
  static async refreshToken(): Promise<string> {
    try {
      const refreshToken = localStorage.getItem('refreshToken');
      if (!refreshToken) {
        throw new Error('No refresh token');
      }

      const response = await axios.post(`${API_URL}/auth/refresh`, {
        refreshToken
      });

      const newToken = response.data.token;
      localStorage.setItem('token', newToken);

      return newToken;
    } catch (error) {
      // If refresh fails, logout
      this.logout();
      throw error;
    }
  }

  /**
   * Get current token
   */
  static getToken(): string | null {
    return localStorage.getItem('token');
  }

  /**
   * Check if user is authenticated
   */
  static isAuthenticated(): boolean {
    return !!this.getToken();
  }
}

export default AuthService;
```

## 3. VAULT SERVICE (Frontend)

```typescript
// src/services/vault.service.ts

import axios from 'axios';
import ClientCryptoService, { EncryptedData } from './crypto.service';

const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:5000/api/v1';

export interface VaultItem {
  id: string;
  title: string;
  website?: string;
  username?: string;
  password: string;
  notes?: string;
  category?: string;
  favorite: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface EncryptedVaultItem {
  id: string;
  encryptedData: string;
  dataIV: string;
  encryptedMetadata: string;
  metadataIV: string;
  itemType: string;
  favorite: boolean;
  createdAt: string;
  updatedAt: string;
}

export class VaultService {
  /**
   * Create new vault item
   */
  static async createItem(
    item: Omit<VaultItem, 'id' | 'createdAt' | 'updatedAt'>,
    dek: CryptoKey
  ): Promise<EncryptedVaultItem> {
    try {
      // Encrypt password
      const encryptedPassword = await ClientCryptoService.encrypt(
        item.password,
        dek
      );

      // Encrypt metadata
      const metadata = {
        title: item.title,
        website: item.website,
        username: item.username,
        notes: item.notes,
        category: item.category
      };
      const encryptedMetadata = await ClientCryptoService.encryptObject(
        metadata,
        dek
      );

      // Send to server
      const token = localStorage.getItem('token');
      const response = await axios.post(
        `${API_URL}/vault/items`,
        {
          encryptedData: encryptedPassword.ciphertext,
          dataIV: encryptedPassword.iv,
          encryptedMetadata: encryptedMetadata.ciphertext,
          metadataIV: encryptedMetadata.iv,
          itemType: 'password',
          favorite: item.favorite
        },
        {
          headers: { Authorization: `Bearer ${token}` }
        }
      );

      return response.data;
    } catch (error: any) {
      throw new Error(error.response?.data?.message || 'Failed to create item');
    }
  }

  /**
   * Get all vault items
   */
  static async getAllItems(): Promise<EncryptedVaultItem[]> {
    try {
      const token = localStorage.getItem('token');
      const response = await axios.get(`${API_URL}/vault/items`, {
        headers: { Authorization: `Bearer ${token}` }
      });

      return response.data;
    } catch (error: any) {
      throw new Error(error.response?.data?.message || 'Failed to fetch items');
    }
  }

  /**
   * Decrypt vault item
   */
  static async decryptItem(
    encryptedItem: EncryptedVaultItem,
    dek: CryptoKey
  ): Promise<VaultItem> {
    try {
      // Decrypt password
      const password = await ClientCryptoService.decrypt(
        {
          ciphertext: encryptedItem.encryptedData,
          iv: encryptedItem.dataIV
        },
        dek
      );

      // Decrypt metadata
      const metadata = await ClientCryptoService.decryptObject<{
        title: string;
        website?: string;
        username?: string;
        notes?: string;
        category?: string;
      }>(
        {
          ciphertext: encryptedItem.encryptedMetadata,
          iv: encryptedItem.metadataIV
        },
        dek
      );

      return {
        id: encryptedItem.id,
        password,
        ...metadata,
        favorite: encryptedItem.favorite,
        createdAt: encryptedItem.createdAt,
        updatedAt: encryptedItem.updatedAt
      };
    } catch (error) {
      throw new Error('Failed to decrypt item');
    }
  }

  /**
   * Update vault item
   */
  static async updateItem(
    itemId: string,
    item: Partial<Omit<VaultItem, 'id' | 'createdAt' | 'updatedAt'>>,
    dek: CryptoKey
  ): Promise<EncryptedVaultItem> {
    try {
      const updates: any = {};

      // Encrypt password if provided
      if (item.password) {
        const encrypted = await ClientCryptoService.encrypt(item.password, dek);
        updates.encryptedData = encrypted.ciphertext;
        updates.dataIV = encrypted.iv;
      }

      // Encrypt metadata if any field provided
      if (item.title || item.website || item.username || item.notes || item.category) {
        const metadata = {
          title: item.title,
          website: item.website,
          username: item.username,
          notes: item.notes,
          category: item.category
        };
        const encrypted = await ClientCryptoService.encryptObject(metadata, dek);
        updates.encryptedMetadata = encrypted.ciphertext;
        updates.metadataIV = encrypted.iv;
      }

      if (item.favorite !== undefined) {
        updates.favorite = item.favorite;
      }

      const token = localStorage.getItem('token');
      const response = await axios.put(
        `${API_URL}/vault/items/${itemId}`,
        updates,
        {
          headers: { Authorization: `Bearer ${token}` }
        }
      );

      return response.data;
    } catch (error: any) {
      throw new Error(error.response?.data?.message || 'Failed to update item');
    }
  }

  /**
   * Delete vault item
   */
  static async deleteItem(itemId: string): Promise<void> {
    try {
      const token = localStorage.getItem('token');
      await axios.delete(`${API_URL}/vault/items/${itemId}`, {
        headers: { Authorization: `Bearer ${token}` }
      });
    } catch (error: any) {
      throw new Error(error.response?.data?.message || 'Failed to delete item');
    }
  }

  /**
   * Copy password to clipboard with auto-clear
   */
  static async copyToClipboard(
    password: string,
    clearAfterSeconds: number = 30
  ): Promise<void> {
    try {
      await navigator.clipboard.writeText(password);
      
      // Auto-clear after timeout
      setTimeout(() => {
        navigator.clipboard.writeText('');
      }, clearAfterSeconds * 1000);
    } catch (error) {
      throw new Error('Failed to copy to clipboard');
    }
  }
}

export default VaultService;
```

## 4. REACT CONTEXT (State Management)

```typescript
// src/contexts/AuthContext.tsx

import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import AuthService, { AuthResponse } from '../services/auth.service';

interface AuthContextType {
  isAuthenticated: boolean;
  user: AuthResponse['user'] | null;
  dek: CryptoKey | null;
  login: (email: string, password: string) => Promise<void>;
  register: (email: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  loading: boolean;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [user, setUser] = useState<AuthResponse['user'] | null>(null);
  const [dek, setDek] = useState<CryptoKey | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Check if user is authenticated on mount
    const token = AuthService.getToken();
    if (token) {
      setIsAuthenticated(true);
      // Note: DEK needs to be re-derived on page refresh
      // User will need to re-enter master password
    }
    setLoading(false);
  }, []);

  const login = async (email: string, masterPassword: string) => {
    try {
      setLoading(true);
      const { authResponse, dek: decryptedDek } = await AuthService.login({
        email,
        masterPassword
      });

      setIsAuthenticated(true);
      setUser(authResponse.user);
      setDek(decryptedDek);
    } catch (error) {
      throw error;
    } finally {
      setLoading(false);
    }
  };

  const register = async (email: string, masterPassword: string) => {
    try {
      setLoading(true);
      await AuthService.register({ email, masterPassword });
      // After registration, automatically login
      await login(email, masterPassword);
    } catch (error) {
      throw error;
    } finally {
      setLoading(false);
    }
  };

  const logout = async () => {
    try {
      await AuthService.logout();
      setIsAuthenticated(false);
      setUser(null);
      setDek(null);
    } catch (error) {
      console.error('Logout error:', error);
    }
  };

  return (
    <AuthContext.Provider
      value={{
        isAuthenticated,
        user,
        dek,
        login,
        register,
        logout,
        loading
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = (): AuthContextType => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within AuthProvider');
  }
  return context;
};
```

Đây là phần code samples quan trọng nhất cho frontend. Tiếp theo tôi sẽ tạo tài liệu deployment và best practices.
