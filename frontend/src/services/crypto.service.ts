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
  // Balanced security and performance
  private static readonly PBKDF2_ITERATIONS = 100000;
  private static readonly PBKDF2_AUTH_ITERATIONS = 10000;
  private static readonly KEY_SIZE = 256;
  private static readonly SALT_SIZE = 32;
  private static readonly IV_SIZE = 12;

  /**
   * Generate random salt for key derivation
   */
  static generateSalt(): string {
    const salt = crypto.getRandomValues(new Uint8Array(this.SALT_SIZE));
    return this.arrayBufferToBase64(salt.buffer);
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

    // Derive Encryption Key (EK) - must be extractable to derive auth key and store
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
      true, // extractable = true
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

    // Import EK back as extractable (needed for 2FA to store temporarily)
    const finalEncryptionKey = await crypto.subtle.importKey(
      'raw',
      ekRaw,
      {
        name: 'AES-GCM',
        length: this.KEY_SIZE
      },
      true,
      ['encrypt', 'decrypt']
    );

    return {
      encryptionKey: finalEncryptionKey,
      authKey: this.arrayBufferToBase64(authKeyBits)
    };
  }

  /**
   * Hash auth key with SHA-256
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
      true,
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
    const dekRaw = await crypto.subtle.exportKey('raw', dek);
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
      iv: this.arrayBufferToBase64(iv.buffer)
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

    return await crypto.subtle.importKey(
      'raw',
      dekRaw,
      {
        name: 'AES-GCM',
        length: this.KEY_SIZE
      },
      true, // extractable = true to allow export to localStorage
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
      iv: this.arrayBufferToBase64(iv.buffer)
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
   * Encrypt object
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

    if (password.length >= 8) score += 1;
    if (password.length >= 12) score += 1;
    if (password.length >= 16) score += 1;
    else feedback.push('Sử dụng ít nhất 16 ký tự');

    if (/[a-z]/.test(password)) score += 1;
    else feedback.push('Thêm chữ thường');
    
    if (/[A-Z]/.test(password)) score += 1;
    else feedback.push('Thêm chữ hoa');
    
    if (/\d/.test(password)) score += 1;
    else feedback.push('Thêm số');
    
    if (/[^A-Za-z0-9]/.test(password)) score += 1;
    else feedback.push('Thêm ký tự đặc biệt');

    const commonPatterns = ['123', 'abc', 'password', 'qwerty'];
    if (commonPatterns.some(p => password.toLowerCase().includes(p))) {
      score -= 2;
      feedback.push('Tránh các mẫu phổ biến');
    }

    let label: 'weak' | 'medium' | 'strong' | 'very_strong';
    if (score <= 3) label = 'weak';
    else if (score <= 5) label = 'medium';
    else if (score <= 6) label = 'strong';
    else label = 'very_strong';

    return { score, label, feedback };
  }

  // Utility methods
  private static arrayBufferToBase64(buffer: ArrayBuffer): string {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }

  private static base64ToArrayBuffer(base64: string): ArrayBuffer {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }

  private static arrayBufferToHex(buffer: ArrayBuffer): string {
    const bytes = new Uint8Array(buffer);
    return Array.from(bytes)
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  }
}

export default ClientCryptoService;
