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

      // Check if 2FA is required - if so, return early without DEK
      if ((authResponse as any).requires2FA) {
        console.log('🔐 [Login] 2FA required, storing encryption key and returning tempToken');
        // Store encryption key temporarily for OTP verification (as hex)
        const encKeyRaw = await crypto.subtle.exportKey('raw', encryptionKey);
        const encKeyHex = Array.from(new Uint8Array(encKeyRaw))
          .map(b => b.toString(16).padStart(2, '0'))
          .join('');
        sessionStorage.setItem('tempEncKey', encKeyHex);
        console.log('✅ [Login] Encryption key stored in sessionStorage');
        return authResponse as any;
      }

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
   * Verify OTP for 2FA
   */
  static async verifyOTP(tempToken: string, otp: string): Promise<{ authResponse: AuthResponse; dek: CryptoKey }> {
    console.log('🔐 [Verify OTP] Starting...');
    
    const response = await apiClient.post('/auth/verify-2fa-login', {
      tempToken,
      otp
    });

    const authResponse: AuthResponse = response.data;
    
    // Decrypt DEK
    console.log('🔐 [Verify OTP] Decrypting DEK...');
    let dek: CryptoKey;
    
    if (authResponse.encryptedDEK === 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB8=') {
      console.log('⚠️ [Verify OTP] Test mode detected - using fixed DEK');
      const fixedKeyData = new Uint8Array(32);
      dek = await crypto.subtle.importKey(
        'raw',
        fixedKeyData,
        { name: 'AES-GCM', length: 256 },
        true,
        ['encrypt', 'decrypt']
      );
    } else {
      // Get encryption key from sessionStorage (stored during login)
      const encKeyHex = sessionStorage.getItem('tempEncKey');
      if (!encKeyHex) {
        console.error('❌ [Verify OTP] Encryption key not found in sessionStorage');
        throw new Error('Encryption key not found. Please login again.');
      }
      
      console.log('🔐 [Verify OTP] Restoring encryption key from hex...');
      const encKeyRaw = new Uint8Array(
        encKeyHex.match(/.{1,2}/g)!.map(byte => parseInt(byte, 16))
      );
      const encryptionKey = await crypto.subtle.importKey(
        'raw',
        encKeyRaw,
        { name: 'AES-GCM', length: 256 },
        true,
        ['encrypt', 'decrypt']
      );
      console.log('✅ [Verify OTP] Encryption key restored successfully');
      
      // Decrypt DEK using encryption key
      console.log('🔐 [Verify OTP] Decrypting DEK with encryption key...');
      console.log('🔍 [Verify OTP] encryptedDEK:', authResponse.encryptedDEK);
      console.log('🔍 [Verify OTP] dekIV:', authResponse.dekIV);
      try {
        const encryptedData = {
          ciphertext: authResponse.encryptedDEK,
          iv: authResponse.dekIV
        };
        dek = await ClientCryptoService.decryptDEK(encryptedData, encryptionKey);
        console.log('✅ [Verify OTP] DEK decrypted successfully');
      } catch (error) {
        console.error('❌ [Verify OTP] Failed to decrypt DEK:', error);
        throw new Error('Failed to decrypt data encryption key. Please try again.');
      }
      
      // Clear temp encryption key
      sessionStorage.removeItem('tempEncKey');
    }

    localStorage.setItem('token', authResponse.token);
    localStorage.setItem('refreshToken', authResponse.refreshToken);

    // Store user and DEK for persistence
    localStorage.setItem('user', JSON.stringify(authResponse.user));
    const dekRaw = await crypto.subtle.exportKey('raw', dek);
    const dekBase64 = btoa(String.fromCharCode(...new Uint8Array(dekRaw)));
    localStorage.setItem('dekRaw', dekBase64);

    console.log('✅ [Verify OTP] Complete!');
    return { authResponse, dek };
  }

  /**
   * Resend OTP
   */
  static async resendOTP(tempToken: string): Promise<void> {
    await apiClient.post('/auth/resend-otp', { tempToken });
  }

  /**
   * Toggle 2FA
   */
  static async toggle2FA(email: string, enabled: boolean): Promise<void> {
    await apiClient.post('/auth/toggle-2fa', { email, enabled });
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
