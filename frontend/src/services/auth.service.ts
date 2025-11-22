import apiClient from './api.service';
import ClientCryptoService from './crypto.service';

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
      const salt = ClientCryptoService.generateSalt();
      const { encryptionKey, authKey } = await ClientCryptoService.deriveMasterKeys(
        data.masterPassword,
        salt
      );

      const authKeyHash = await ClientCryptoService.hashAuthKey(authKey);
      const dek = await ClientCryptoService.generateDEK();
      const encryptedDEK = await ClientCryptoService.encryptDEK(dek, encryptionKey);

      const response = await apiClient.post('/auth/register', {
        email: data.email,
        authKeyHash,
        salt,
        encryptedDEK: encryptedDEK.ciphertext,
        dekIV: encryptedDEK.iv
      });

      return response.data;
    } catch (error: any) {
      throw new Error(error.response?.data?.message || 'Đăng ký thất bại');
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
      console.log('🔐 [Login] Step 1: Getting salt for email:', data.email);
      const saltResponse = await apiClient.post('/auth/get-salt', {
        email: data.email
      });
      const salt = saltResponse.data.data.salt;
      console.log('✅ [Login] Step 2: Salt received:', salt.substring(0, 20) + '...');

      console.log('🔐 [Login] Step 3: Deriving master keys...');
      const { encryptionKey, authKey } = await ClientCryptoService.deriveMasterKeys(
        data.masterPassword,
        salt
      );
      console.log('✅ [Login] Step 4: Master keys derived');

      console.log('🔐 [Login] Step 5: Hashing auth key...');
      const authKeyHash = await ClientCryptoService.hashAuthKey(authKey);
      console.log('✅ [Login] Step 6: Auth key hashed:', authKeyHash.substring(0, 20) + '...');

      console.log('🔐 [Login] Step 7: Calling login API...');
      const response = await apiClient.post('/auth/login', {
        email: data.email,
        authKeyHash
      });
      console.log('✅ [Login] Step 8: Login response received:', response.data);

      const authResponse: AuthResponse = response.data;

      console.log('🔐 [Login] Step 9: Decrypting DEK...');
      let dek: CryptoKey;
      
      // TEST MODE: If DEK is test value, use fixed DEK for consistency across sessions
      if (authResponse.encryptedDEK === 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB8=') {
        console.log('⚠️ [Login] Test mode detected - using fixed DEK');
        // Use a fixed 32-byte key (all zeros) for test mode
        // This ensures the same DEK is used every time, so vault data persists
        const fixedKeyData = new Uint8Array(32); // All zeros
        dek = await crypto.subtle.importKey(
          'raw',
          fixedKeyData,
          { name: 'AES-GCM', length: 256 },
          true,
          ['encrypt', 'decrypt']
        );
      } else {
        dek = await ClientCryptoService.decryptDEK(
          {
            ciphertext: authResponse.encryptedDEK,
            iv: authResponse.dekIV
          },
          encryptionKey
        );
      }
      console.log('✅ [Login] Step 10: DEK ready');

      localStorage.setItem('token', authResponse.token);
      localStorage.setItem('refreshToken', authResponse.refreshToken);
      console.log('✅ [Login] Complete! Tokens saved to localStorage');

      return { authResponse, dek };
    } catch (error: any) {
      console.error('❌ [Login] Error:', error);
      console.error('❌ [Login] Error response:', error.response?.data);
      throw new Error(error.response?.data?.message || 'Đăng nhập thất bại');
    }
  }

  /**
   * Logout
   */
  static async logout(): Promise<void> {
    try {
      await apiClient.post('/auth/logout');
    } catch (error) {
      // Ignore errors
    } finally {
      localStorage.removeItem('token');
      localStorage.removeItem('refreshToken');
    }
  }

  /**
   * Get current token
   */
  static getToken(): string | null {
    return localStorage.getItem('token');
  }

  /**
   * Check if authenticated
   */
  static isAuthenticated(): boolean {
    return !!this.getToken();
  }
}

export default AuthService;
