import * as crypto from 'crypto';
import * as argon2 from 'argon2';
import config from '../config';

export interface EncryptionResult {
  ciphertext: string;
  iv: string;
  authTag: string;
}

export interface DecryptionInput {
  ciphertext: string;
  iv: string;
  authTag: string;
}

/**
 * Server-side Encryption Service
 * Note: This provides an additional encryption layer on the server.
 * The primary encryption happens on the client side (zero-knowledge).
 */
export class EncryptionService {
  private static readonly ALGORITHM = 'aes-256-gcm';
  private static readonly IV_LENGTH = 12; // 96 bits for GCM
  // private static readonly AUTH_TAG_LENGTH = 16; // 128 bits
  private static readonly KEY_LENGTH = 32; // 256 bits

  /**
   * Get server encryption key from environment
   * In production, this should come from KMS
   */
  private static getServerKey(): Buffer {
    const key = config.encryption.serverKey;
    
    if (!key) {
      throw new Error('Server encryption key not configured');
    }

    // Ensure key is 32 bytes (256 bits)
    const keyBuffer = Buffer.from(key, 'base64');
    
    if (keyBuffer.length !== this.KEY_LENGTH) {
      throw new Error(`Invalid key length: expected ${this.KEY_LENGTH} bytes`);
    }

    return keyBuffer;
  }

  /**
   * Encrypt data with AES-256-GCM
   */
  static encrypt(plaintext: string): EncryptionResult {
    try {
      const key = this.getServerKey();
      const iv = crypto.randomBytes(this.IV_LENGTH);
      
      const cipher = crypto.createCipheriv(this.ALGORITHM, key, iv);
      
      let ciphertext = cipher.update(plaintext, 'utf8', 'base64');
      ciphertext += cipher.final('base64');
      
      const authTag = cipher.getAuthTag();

      return {
        ciphertext,
        iv: iv.toString('base64'),
        authTag: authTag.toString('base64')
      };
    } catch (error) {
      throw new Error(`Encryption failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Decrypt data with AES-256-GCM
   */
  static decrypt(input: DecryptionInput): string {
    try {
      const key = this.getServerKey();
      const iv = Buffer.from(input.iv, 'base64');
      const authTag = Buffer.from(input.authTag, 'base64');
      
      const decipher = crypto.createDecipheriv(this.ALGORITHM, key, iv);
      decipher.setAuthTag(authTag);
      
      let plaintext = decipher.update(input.ciphertext, 'base64', 'utf8');
      plaintext += decipher.final('utf8');
      
      return plaintext;
    } catch (error) {
      throw new Error(`Decryption failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Hash password with Argon2id
   * Used for hashing auth keys
   */
  static async hashPassword(password: string): Promise<string> {
    try {
      return await argon2.hash(password, {
        type: argon2.argon2id,
        memoryCost: config.security.argon2MemoryCost,
        timeCost: config.security.argon2TimeCost,
        parallelism: config.security.argon2Parallelism
      });
    } catch (error) {
      throw new Error(`Password hashing failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Verify password hash with Argon2id
   */
  static async verifyPassword(hash: string, password: string): Promise<boolean> {
    try {
      return await argon2.verify(hash, password);
    } catch (error) {
      return false;
    }
  }

  /**
   * Generate cryptographically secure random bytes
   */
  static generateRandomBytes(length: number): Buffer {
    return crypto.randomBytes(length);
  }

  /**
   * Generate random hex string
   */
  static generateRandomHex(length: number): string {
    return crypto.randomBytes(length).toString('hex');
  }

  /**
   * Generate random base64 string
   */
  static generateRandomBase64(length: number): string {
    return crypto.randomBytes(length).toString('base64');
  }

  /**
   * Hash data with SHA-256
   */
  static sha256(data: string): string {
    return crypto.createHash('sha256').update(data).digest('hex');
  }

  /**
   * HMAC with SHA-256
   */
  static hmacSha256(data: string, key: string): string {
    return crypto.createHmac('sha256', key).update(data).digest('hex');
  }

  /**
   * Constant-time string comparison (prevents timing attacks)
   */
  static constantTimeCompare(a: string, b: string): boolean {
    if (a.length !== b.length) {
      return false;
    }

    const bufferA = Buffer.from(a);
    const bufferB = Buffer.from(b);

    return crypto.timingSafeEqual(bufferA, bufferB);
  }

  /**
   * Generate encryption key
   */
  static generateEncryptionKey(bits: number = 256): Buffer {
    return crypto.randomBytes(bits / 8);
  }

  /**
   * Derive key using PBKDF2
   * (This is primarily for client-side, but provided for reference)
   */
  static deriveKeyPBKDF2(
    password: string,
    salt: string,
    iterations: number = 600000,
    keyLength: number = 32
  ): Buffer {
    return crypto.pbkdf2Sync(
      password,
      salt,
      iterations,
      keyLength,
      'sha256'
    );
  }
}

export default EncryptionService;
