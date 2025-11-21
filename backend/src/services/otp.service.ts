import { authenticator } from 'otplib';
import QRCode from 'qrcode';
import crypto from 'crypto';
import { logger } from '../config/logger';

export interface TOTPSetup {
  secret: string;
  qrCodeUrl: string;
  manualEntryCode: string;
}

export interface OTPValidationResult {
  isValid: boolean;
  message: string;
}

export class OTPService {
  private static readonly APP_NAME = 'Password Manager';
  private static readonly OTP_WINDOW = 1; // Allow 1 step before/after
  private static readonly OTP_EXPIRY_MINUTES = 5;

  /**
   * Generate TOTP secret for 2FA
   */
  static generateTOTPSecret(): string {
    return authenticator.generateSecret();
  }

  /**
   * Generate QR code for TOTP setup
   */
  static async setupTOTP(email: string, secret: string): Promise<TOTPSetup> {
    try {
      // Generate OTP Auth URL
      const otpAuthUrl = authenticator.keyuri(
        email,
        this.APP_NAME,
        secret
      );

      // Generate QR code
      const qrCodeUrl = await QRCode.toDataURL(otpAuthUrl);

      // Format secret for manual entry (groups of 4)
      const manualEntryCode = secret.match(/.{1,4}/g)?.join(' ') || secret;

      return {
        secret,
        qrCodeUrl,
        manualEntryCode
      };
    } catch (error) {
      logger.error('TOTP setup error:', error);
      throw new Error('Failed to setup TOTP');
    }
  }

  /**
   * Verify TOTP code
   */
  static verifyTOTP(token: string, secret: string): OTPValidationResult {
    try {
      const isValid = authenticator.check(token, secret);

      return {
        isValid,
        message: isValid ? 'Valid OTP' : 'Invalid OTP code'
      };
    } catch (error) {
      logger.error('TOTP verification error:', error);
      return {
        isValid: false,
        message: 'OTP verification failed'
      };
    }
  }

  /**
   * Generate time-limited OTP for email/SMS (6 digits)
   */
  static generateEmailOTP(): { code: string; expiresAt: Date } {
    const code = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = new Date();
    expiresAt.setMinutes(expiresAt.getMinutes() + this.OTP_EXPIRY_MINUTES);

    return { code, expiresAt };
  }

  /**
   * Generate backup codes for 2FA recovery
   */
  static generateBackupCodes(count: number = 10): string[] {
    const codes: string[] = [];
    for (let i = 0; i < count; i++) {
      const code = crypto.randomBytes(4).toString('hex').toUpperCase();
      codes.push(code.match(/.{1,4}/g)?.join('-') || code);
    }
    return codes;
  }

  /**
   * Encrypt external secret (for storing 3rd party TOTP secrets)
   */
  static encryptSecret(secret: string, userKey: string): string {
    const algorithm = 'aes-256-gcm';
    const key = crypto.scryptSync(userKey, 'salt', 32);
    const iv = crypto.randomBytes(16);
    
    const cipher = crypto.createCipheriv(algorithm, key, iv);
    let encrypted = cipher.update(secret, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    const authTag = cipher.getAuthTag();
    
    // Return: iv:authTag:encrypted
    return `${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted}`;
  }

  /**
   * Decrypt external secret
   */
  static decryptSecret(encryptedSecret: string, userKey: string): string {
    try {
      const algorithm = 'aes-256-gcm';
      const key = crypto.scryptSync(userKey, 'salt', 32);
      
      const parts = encryptedSecret.split(':');
      const iv = Buffer.from(parts[0], 'hex');
      const authTag = Buffer.from(parts[1], 'hex');
      const encrypted = parts[2];
      
      const decipher = crypto.createDecipheriv(algorithm, key, iv);
      decipher.setAuthTag(authTag);
      
      let decrypted = decipher.update(encrypted, 'hex', 'utf8');
      decrypted += decipher.final('utf8');
      
      return decrypted;
    } catch (error) {
      logger.error('Secret decryption error:', error);
      throw new Error('Failed to decrypt secret');
    }
  }

  /**
   * Generate current TOTP code (for testing/display)
   */
  static generateCurrentTOTP(secret: string): string {
    return authenticator.generate(secret);
  }

  /**
   * Get time remaining until next TOTP code
   */
  static getTimeRemaining(): number {
    const epoch = Math.floor(Date.now() / 1000);
    const timeStep = 30; // TOTP uses 30-second time steps
    return timeStep - (epoch % timeStep);
  }
}

export default OTPService;
