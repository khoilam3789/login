import AWS from 'aws-sdk';
import * as crypto from 'crypto';
import config from '../config';
import { logger } from '../config/logger';

export interface KeyMetadata {
  keyId: string;
  version: number;
  algorithm: string;
  createdAt: Date;
  status: 'active' | 'rotated' | 'revoked' | 'scheduled_deletion';
}

export interface EncryptedKey {
  encryptedKey: string;
  kmsKeyId: string;
  metadata: KeyMetadata;
}

/**
 * Key Management Service
 * Handles encryption keys lifecycle and AWS KMS integration
 */
export class KeyManagementService {
  private kms: AWS.KMS;
  private kmsKeyId: string;

  constructor() {
    // Initialize AWS KMS
    AWS.config.update({
      region: config.aws.region,
      accessKeyId: config.aws.accessKeyId,
      secretAccessKey: config.aws.secretAccessKey
    });

    this.kms = new AWS.KMS();
    this.kmsKeyId = config.aws.kmsKeyId;
  }

  /**
   * Generate new Data Encryption Key (DEK)
   */
  generateDEK(bits: number = 256): Buffer {
    return crypto.randomBytes(bits / 8);
  }

  /**
   * Encrypt DEK with KMS Master Key
   */
  async encryptWithKMS(plainKey: Buffer): Promise<string> {
    try {
      if (!this.kmsKeyId) {
        // If KMS not configured, fall back to local encryption
        logger.warn('KMS not configured, using local encryption');
        return this.encryptLocally(plainKey);
      }

      const params = {
        KeyId: this.kmsKeyId,
        Plaintext: plainKey
      };

      const result = await this.kms.encrypt(params).promise();
      
      if (!result.CiphertextBlob) {
        throw new Error('KMS encryption failed: no ciphertext returned');
      }

      return result.CiphertextBlob.toString('base64');
    } catch (error) {
      logger.error('KMS encryption error:', error);
      throw new Error(`Failed to encrypt with KMS: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Decrypt DEK with KMS Master Key
   */
  async decryptWithKMS(encryptedKey: string): Promise<Buffer> {
    try {
      if (!this.kmsKeyId) {
        // If KMS not configured, fall back to local decryption
        logger.warn('KMS not configured, using local decryption');
        return this.decryptLocally(encryptedKey);
      }

      const params = {
        CiphertextBlob: Buffer.from(encryptedKey, 'base64')
      };

      const result = await this.kms.decrypt(params).promise();
      
      if (!result.Plaintext) {
        throw new Error('KMS decryption failed: no plaintext returned');
      }

      return Buffer.from(result.Plaintext as Uint8Array);
    } catch (error) {
      logger.error('KMS decryption error:', error);
      throw new Error(`Failed to decrypt with KMS: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Generate Data Key using KMS
   * Returns both plaintext and encrypted versions
   */
  async generateDataKey(keySpec: 'AES_256' | 'AES_128' = 'AES_256'): Promise<{
    plaintext: Buffer;
    encrypted: string;
  }> {
    try {
      if (!this.kmsKeyId) {
        // Local fallback
        const plaintext = this.generateDEK(keySpec === 'AES_256' ? 256 : 128);
        const encrypted = this.encryptLocally(plaintext);
        return { plaintext, encrypted };
      }

      const params = {
        KeyId: this.kmsKeyId,
        KeySpec: keySpec
      };

      const result = await this.kms.generateDataKey(params).promise();
      
      if (!result.Plaintext || !result.CiphertextBlob) {
        throw new Error('Failed to generate data key');
      }

      return {
        plaintext: Buffer.from(result.Plaintext as Uint8Array),
        encrypted: result.CiphertextBlob.toString('base64')
      };
    } catch (error) {
      logger.error('Generate data key error:', error);
      throw error;
    }
  }

  /**
   * Create new KMS key
   */
  async createKMSKey(description: string): Promise<string> {
    try {
      const params = {
        Description: description,
        KeyUsage: 'ENCRYPT_DECRYPT' as const,
        Origin: 'AWS_KMS' as const
      };

      const result = await this.kms.createKey(params).promise();
      
      if (!result.KeyMetadata?.KeyId) {
        throw new Error('Failed to create KMS key');
      }

      logger.info(`Created new KMS key: ${result.KeyMetadata.KeyId}`);
      return result.KeyMetadata.KeyId;
    } catch (error) {
      logger.error('Create KMS key error:', error);
      throw error;
    }
  }

  /**
   * Rotate master key
   */
  async rotateMasterKey(): Promise<void> {
    try {
      const params = {
        KeyId: this.kmsKeyId
      };

      await this.kms.enableKeyRotation(params).promise();
      logger.info('Enabled automatic key rotation for master key');
    } catch (error) {
      logger.error('Key rotation error:', error);
      throw error;
    }
  }

  /**
   * Schedule key deletion
   */
  async scheduleKeyDeletion(keyId: string, pendingWindowInDays: number = 30): Promise<void> {
    try {
      const params = {
        KeyId: keyId,
        PendingWindowInDays: pendingWindowInDays
      };

      await this.kms.scheduleKeyDeletion(params).promise();
      logger.info(`Scheduled deletion for key ${keyId} in ${pendingWindowInDays} days`);
    } catch (error) {
      logger.error('Schedule key deletion error:', error);
      throw error;
    }
  }

  /**
   * Disable key
   */
  async disableKey(keyId: string): Promise<void> {
    try {
      const params = {
        KeyId: keyId
      };

      await this.kms.disableKey(params).promise();
      logger.info(`Disabled key ${keyId}`);
    } catch (error) {
      logger.error('Disable key error:', error);
      throw error;
    }
  }

  /**
   * Get key info
   */
  async getKeyInfo(keyId: string): Promise<AWS.KMS.KeyMetadata | null> {
    try {
      const params = {
        KeyId: keyId
      };

      const result = await this.kms.describeKey(params).promise();
      return result.KeyMetadata || null;
    } catch (error) {
      logger.error('Get key info error:', error);
      return null;
    }
  }

  /**
   * Local encryption fallback (when KMS not available)
   * Uses server encryption key
   */
  private encryptLocally(plaintext: Buffer): string {
    const serverKey = Buffer.from(config.encryption.serverKey, 'base64');
    const iv = crypto.randomBytes(12);
    
    const cipher = crypto.createCipheriv('aes-256-gcm', serverKey, iv);
    
    const encrypted = Buffer.concat([
      cipher.update(plaintext),
      cipher.final()
    ]);
    
    const authTag = cipher.getAuthTag();
    
    // Combine iv + authTag + encrypted
    const combined = Buffer.concat([iv, authTag, encrypted]);
    
    return combined.toString('base64');
  }

  /**
   * Local decryption fallback
   */
  private decryptLocally(encryptedData: string): Buffer {
    const serverKey = Buffer.from(config.encryption.serverKey, 'base64');
    const combined = Buffer.from(encryptedData, 'base64');
    
    // Extract components
    const iv = combined.slice(0, 12);
    const authTag = combined.slice(12, 28);
    const encrypted = combined.slice(28);
    
    const decipher = crypto.createDecipheriv('aes-256-gcm', serverKey, iv);
    decipher.setAuthTag(authTag);
    
    const decrypted = Buffer.concat([
      decipher.update(encrypted),
      decipher.final()
    ]);
    
    return decrypted;
  }

  /**
   * Generate key metadata
   */
  generateKeyMetadata(version: number = 1): KeyMetadata {
    return {
      keyId: crypto.randomUUID(),
      version,
      algorithm: 'AES-256-GCM',
      createdAt: new Date(),
      status: 'active'
    };
  }

  /**
   * Re-encrypt data with new key (for key rotation)
   */
  async reencryptData(
    encryptedData: string,
    oldKey: Buffer,
    newKey: Buffer
  ): Promise<string> {
    try {
      // This is a simplified version
      // In practice, you'd use KMS ReEncrypt API
      const combined = Buffer.from(encryptedData, 'base64');
      
      // Extract components
      const iv = combined.slice(0, 12);
      const authTag = combined.slice(12, 28);
      const encrypted = combined.slice(28);
      
      // Decrypt with old key
      const decipher = crypto.createDecipheriv('aes-256-gcm', oldKey, iv);
      decipher.setAuthTag(authTag);
      const plaintext = Buffer.concat([
        decipher.update(encrypted),
        decipher.final()
      ]);
      
      // Encrypt with new key
      const newIv = crypto.randomBytes(12);
      const cipher = crypto.createCipheriv('aes-256-gcm', newKey, newIv);
      const newEncrypted = Buffer.concat([
        cipher.update(plaintext),
        cipher.final()
      ]);
      const newAuthTag = cipher.getAuthTag();
      
      // Combine and return
      const newCombined = Buffer.concat([newIv, newAuthTag, newEncrypted]);
      return newCombined.toString('base64');
    } catch (error) {
      throw new Error(`Re-encryption failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }
}

export default new KeyManagementService();
