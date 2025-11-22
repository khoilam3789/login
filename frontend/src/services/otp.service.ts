import apiClient from './api.service';

export interface OTPSession {
  sessionId: string;
  otpCode: string;
  expiresAt: string;
}

export interface ExternalSecret {
  id: string;
  label: string;
  secret: string;
  issuer?: string;
  algorithm: 'SHA1' | 'SHA256' | 'SHA512';
  digits: 6 | 8;
  period: number;
  createdAt: string;
}

export class OTPService {
  /**
   * Request OTP code
   */
  static async requestOTP(): Promise<OTPSession> {
    try {
      const response = await apiClient.post('/otp/request');
      return response.data;
    } catch (error: any) {
      throw new Error(error.response?.data?.message || 'Không thể yêu cầu OTP');
    }
  }

  /**
   * Verify OTP code
   */
  static async verifyOTP(sessionId: string, otpCode: string): Promise<boolean> {
    try {
      const response = await apiClient.post('/otp/verify', {
        sessionId,
        otpCode
      });
      return response.data.valid;
    } catch (error: any) {
      throw new Error(error.response?.data?.message || 'Xác thực OTP thất bại');
    }
  }

  /**
   * Get all external secrets
   */
  static async getExternalSecrets(): Promise<ExternalSecret[]> {
    try {
      const response = await apiClient.get('/otp/external-secrets');
      const backendSecrets = response.data.data || [];
      
      // Map backend fields to frontend interface
      return backendSecrets.map((item: any) => ({
        id: item._id,
        label: item.name,
        secret: '', // Don't expose secret in list view
        issuer: item.issuer,
        algorithm: 'SHA1' as const,
        digits: 6 as const,
        period: 30,
        createdAt: item.createdAt
      }));
    } catch (error: any) {
      throw new Error(error.response?.data?.message || 'Không thể tải dữ liệu');
    }
  }

  /**
   * Add external secret
   */
  static async addExternalSecret(secret: Omit<ExternalSecret, 'id' | 'createdAt'>): Promise<ExternalSecret> {
    try {
      // Map frontend fields to backend fields
      const payload = {
        name: secret.label,
        issuer: secret.issuer || 'Unknown',
        encryptedSecret: secret.secret, // TODO: Encrypt this with DEK
        accountName: secret.label,
        category: 'other', // Use valid enum value
        notes: ''
      };
      
      const response = await apiClient.post('/otp/external-secrets', payload);
      return response.data.data; // Backend returns { success, data }
    } catch (error: any) {
      console.error('Add external secret error:', error.response?.data);
      throw new Error(error.response?.data?.message || 'Không thể thêm secret');
    }
  }

  /**
   * Update external secret
   */
  static async updateExternalSecret(
    id: string,
    secret: Partial<Omit<ExternalSecret, 'id' | 'createdAt'>>
  ): Promise<ExternalSecret> {
    try {
      const response = await apiClient.put(`/otp/external-secrets/${id}`, secret);
      return response.data.secret;
    } catch (error: any) {
      throw new Error(error.response?.data?.message || 'Không thể cập nhật');
    }
  }

  /**
   * Delete external secret
   */
  static async deleteExternalSecret(id: string): Promise<void> {
    try {
      await apiClient.delete(`/otp/external-secrets/${id}`);
    } catch (error: any) {
      throw new Error(error.response?.data?.message || 'Không thể xóa secret');
    }
  }

  /**
   * Get single external secret with encrypted secret
   */
  static async getExternalSecret(id: string): Promise<string> {
    try {
      const response = await apiClient.get(`/otp/external-secrets/${id}`);
      return response.data.data?.encryptedSecret || '';
    } catch (error: any) {
      throw new Error(error.response?.data?.message || 'Không thể tải secret');
    }
  }

  /**
   * Generate TOTP code client-side
   */
  static async generateTOTP(
    secret: string,
    period: number = 30,
    digits: number = 6
  ): Promise<string> {
    const epoch = Math.floor(Date.now() / 1000);
    const counter = Math.floor(epoch / period);

    // Decode base32 secret
    const secretBytes = this.base32Decode(secret);

    // HMAC-SHA1
    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey(
      'raw',
      secretBytes,
      { name: 'HMAC', hash: 'SHA-1' },
      false,
      ['sign']
    );

    const counterBytes = new ArrayBuffer(8);
    const counterView = new DataView(counterBytes);
    counterView.setBigUint64(0, BigInt(counter), false);

    const signature = await crypto.subtle.sign('HMAC', key, counterBytes);
    const signatureArray = new Uint8Array(signature);

    // Dynamic truncation
    const offset = signatureArray[signatureArray.length - 1] & 0x0f;
    const binary =
      ((signatureArray[offset] & 0x7f) << 24) |
      ((signatureArray[offset + 1] & 0xff) << 16) |
      ((signatureArray[offset + 2] & 0xff) << 8) |
      (signatureArray[offset + 3] & 0xff);

    const otp = binary % Math.pow(10, digits);
    return otp.toString().padStart(digits, '0');
  }

  /**
   * Base32 decode
   */
  private static base32Decode(encoded: string): Uint8Array {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    const cleanedInput = encoded.toUpperCase().replace(/[^A-Z2-7]/g, '');
    
    let bits = 0;
    let value = 0;
    const output: number[] = [];

    for (let i = 0; i < cleanedInput.length; i++) {
      value = (value << 5) | alphabet.indexOf(cleanedInput[i]);
      bits += 5;

      if (bits >= 8) {
        output.push((value >>> (bits - 8)) & 255);
        bits -= 8;
      }
    }

    return new Uint8Array(output);
  }
}

export default OTPService;
