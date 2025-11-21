# Kiến Trúc Hệ Thống Quản Lý Mật Khẩu An Toàn

## 1. TỔNG QUAN KIẾN TRÚC

### 1.1 Sơ Đồ Kiến Trúc Tổng Thể

```
┌─────────────────────────────────────────────────────────────┐
│                         CLIENT SIDE                          │
├─────────────────────────────────────────────────────────────┤
│  ReactJS + TypeScript + Tailwind CSS                         │
│  ┌────────────────────────────────────────────────────┐     │
│  │  • Crypto Module (Web Crypto API)                  │     │
│  │  • Master Password → PBKDF2 → Encryption Key       │     │
│  │  • Client-side Encryption/Decryption               │     │
│  │  • Zero-Knowledge Architecture                     │     │
│  └────────────────────────────────────────────────────┘     │
└─────────────────────────────────────────────────────────────┘
                            ↕ HTTPS + JWT
┌─────────────────────────────────────────────────────────────┐
│                      MIDDLEWARE LAYER                        │
├─────────────────────────────────────────────────────────────┤
│  • Authentication (JWT Verification)                         │
│  • Rate Limiting (Express Rate Limit)                        │
│  • Input Validation (Joi/Zod)                                │
│  • Request Sanitization                                      │
│  • CORS Configuration                                        │
│  • Security Headers (Helmet.js)                              │
└─────────────────────────────────────────────────────────────┘
                            ↕
┌─────────────────────────────────────────────────────────────┐
│                      BACKEND (Node.js)                       │
├─────────────────────────────────────────────────────────────┤
│  Express + TypeScript - MVC Pattern                          │
│                                                               │
│  ┌─────────────────────────────────────────────────────┐   │
│  │              CONTROLLER LAYER                        │   │
│  │  • AuthController                                    │   │
│  │  • VaultController                                   │   │
│  │  • OTPController                                     │   │
│  │  • KeyManagementController                          │   │
│  └─────────────────────────────────────────────────────┘   │
│                            ↕                                 │
│  ┌─────────────────────────────────────────────────────┐   │
│  │               SERVICE LAYER                          │   │
│  │  • AuthService (JWT, Password Hashing)              │   │
│  │  • EncryptionService (AES-256-GCM)                  │   │
│  │  • OTPService (Generation, Verification)            │   │
│  │  • KeyManagementService (KMS Integration)           │   │
│  │  • AuditService (Security Logging)                  │   │
│  └─────────────────────────────────────────────────────┘   │
│                            ↕                                 │
│  ┌─────────────────────────────────────────────────────┐   │
│  │            REPOSITORY/MODEL LAYER                    │   │
│  │  • UserRepository                                    │   │
│  │  • VaultItemRepository                              │   │
│  │  • OTPRepository                                     │   │
│  │  • AuditLogRepository                               │   │
│  │  • KeyRepository                                     │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
                            ↕
┌─────────────────────────────────────────────────────────────┐
│                        MONGODB                               │
├─────────────────────────────────────────────────────────────┤
│  Collections:                                                │
│  • users (encrypted master key hash)                         │
│  • vault_items (encrypted passwords)                         │
│  • otp_sessions (temporary OTP data)                         │
│  • audit_logs (security events)                              │
│  • encryption_keys (versioned keys)                          │
│  • external_otp_secrets (encrypted 2FA secrets)              │
└─────────────────────────────────────────────────────────────┘
                            ↕
┌─────────────────────────────────────────────────────────────┐
│                   EXTERNAL SERVICES                          │
├─────────────────────────────────────────────────────────────┤
│  • KMS (AWS KMS / Azure Key Vault / HashiCorp Vault)        │
│  • Email Service (SendGrid / AWS SES)                        │
│  • SMS Service (Twilio)                                      │
└─────────────────────────────────────────────────────────────┘
```

## 2. MÔ HÌNH ZERO-KNOWLEDGE

### 2.1 Nguyên Tắc Cốt Lõi

**Zero-Knowledge** có nghĩa là server không bao giờ biết:
- Master password của người dùng
- Encryption key dùng để mã hóa vault
- Plaintext của các mật khẩu được lưu trữ

### 2.2 Luồng Hoạt Động Chi Tiết

#### A. Đăng Ký (Registration)

```
CLIENT:
1. User nhập Master Password (MP)
2. Generate random salt (32 bytes)
3. Derive Encryption Key: 
   EK = PBKDF2(MP, salt, 600000 iterations, 256 bits)
4. Derive Auth Key (để xác thực với server):
   AK = PBKDF2(EK, "auth", 100000 iterations, 256 bits)
5. Hash Auth Key để lưu trữ:
   AK_Hash = Argon2id(AK)
6. Generate random Master Key Encryption Key (MKEK - 256 bits)
7. Generate random Data Encryption Key (DEK - 256 bits)
8. Encrypt DEK with EK:
   DEK_encrypted = AES-256-GCM(DEK, key=EK, random_iv)
   
SEND TO SERVER:
{
  email: "user@example.com",
  authKeyHash: AK_Hash,
  salt: salt (base64),
  encryptedDEK: DEK_encrypted (base64),
  dekIV: iv (base64)
}

SERVER:
1. Validate input
2. Hash authKeyHash again with Argon2id (double hashing)
3. Store in database
4. Server NEVER có MP, EK, hoặc DEK plaintext
```

#### B. Đăng Nhập (Login)

```
CLIENT:
1. User nhập Master Password
2. Fetch salt từ server
3. Derive EK = PBKDF2(MP, salt, 600000 iterations, 256 bits)
4. Derive AK = PBKDF2(EK, "auth", 100000 iterations, 256 bits)
5. Hash AK: AK_Hash = Argon2id(AK)

SEND TO SERVER:
{
  email: "user@example.com",
  authKeyHash: AK_Hash
}

SERVER:
1. Verify authKeyHash
2. Return JWT token + encryptedDEK
3. Server vẫn KHÔNG biết EK

CLIENT:
4. Decrypt DEK: DEK = AES-256-GCM-Decrypt(encryptedDEK, key=EK)
5. Store DEK in memory (SessionStorage/Memory only, NEVER localStorage)
6. Use DEK to encrypt/decrypt vault items
```

#### C. Lưu Mật Khẩu (Save Password)

```
CLIENT:
1. User nhập password cần lưu
2. Generate random IV (12 bytes for GCM)
3. Encrypt: 
   ciphertext = AES-256-GCM(password, key=DEK, iv=IV)
   (GCM provides authentication tag automatically)
4. Generate metadata IV
5. Encrypt metadata (website, username):
   metadata_encrypted = AES-256-GCM(metadata, key=DEK, iv=metadata_IV)

SEND TO SERVER:
{
  ciphertext: base64(ciphertext + authTag),
  iv: base64(iv),
  encryptedMetadata: base64(metadata_encrypted),
  metadataIV: base64(metadata_iv)
}

SERVER:
1. Validate JWT
2. Store encrypted data
3. Server KHÔNG THỂ decrypt vì không có DEK
```

#### D. Đọc Mật Khẩu (Retrieve Password)

```
SERVER → CLIENT:
Return encrypted data + IV

CLIENT:
1. Decrypt: password = AES-256-GCM-Decrypt(ciphertext, key=DEK, iv=IV)
2. Verify authentication tag (automatic in GCM mode)
3. Display to user
```

#### E. Thay Đổi Master Password

```
CLIENT:
1. User nhập Old MP và New MP
2. Derive old EK từ Old MP
3. Decrypt DEK với old EK
4. Derive new EK từ New MP
5. Generate new salt
6. Re-encrypt DEK với new EK
7. Derive new AK từ new EK
8. Hash new AK

SEND TO SERVER:
{
  oldAuthKeyHash: old_AK_Hash,
  newAuthKeyHash: new_AK_Hash,
  newSalt: new_salt,
  newEncryptedDEK: new_DEK_encrypted,
  newDEKIV: new_iv
}

SERVER:
1. Verify oldAuthKeyHash
2. Update to new credentials
3. Vault items KHÔNG CẦN re-encrypt (vì DEK không đổi)
```

### 2.3 Key Hierarchy

```
Master Password (Only in user's head)
    ↓ PBKDF2 (600k iterations)
Encryption Key (EK) - Client memory only
    ↓ 
    ├→ PBKDF2 → Auth Key (AK) → Server (hashed)
    └→ Encrypts DEK → Stored on server (encrypted)
            ↓
Data Encryption Key (DEK) - Client memory only
    ↓
Encrypts all vault items
```

## 3. MÃ HÓA DỮ LIỆU (ENCRYPTION AT REST)

### 3.1 Thuật Toán: AES-256-GCM

**Lý do chọn AES-256-GCM:**
- **AES-256**: Mã hóa khối mạnh, được NIST chứng nhận
- **GCM Mode**: 
  - Authenticated Encryption (tự động kiểm tra tính toàn vẹn)
  - Nhanh hơn CBC mode
  - Không cần HMAC riêng
  - Tránh padding oracle attacks

### 3.2 Implementation

```typescript
// CLIENT SIDE
import { AES, GCM, PBKDF2, SHA256 } from 'crypto-js';

class CryptoService {
  // Derive key from master password
  static deriveEncryptionKey(
    masterPassword: string, 
    salt: string, 
    iterations: number = 600000
  ): string {
    return PBKDF2(masterPassword, salt, {
      keySize: 256 / 32,
      iterations: iterations,
      hasher: SHA256
    }).toString();
  }

  // Encrypt data
  static encrypt(plaintext: string, key: string): {
    ciphertext: string;
    iv: string;
    tag: string;
  } {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    
    // Use Web Crypto API for better security
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      enc.encode(key),
      { name: 'AES-GCM' },
      false,
      ['encrypt']
    );

    const encrypted = await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: iv,
        tagLength: 128
      },
      keyMaterial,
      enc.encode(plaintext)
    );

    return {
      ciphertext: Buffer.from(encrypted).toString('base64'),
      iv: Buffer.from(iv).toString('base64')
    };
  }

  // Decrypt data
  static async decrypt(
    ciphertext: string, 
    key: string, 
    iv: string
  ): Promise<string> {
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      Buffer.from(key, 'base64'),
      { name: 'AES-GCM' },
      false,
      ['decrypt']
    );

    const decrypted = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: Buffer.from(iv, 'base64'),
        tagLength: 128
      },
      keyMaterial,
      Buffer.from(ciphertext, 'base64')
    );

    const dec = new TextDecoder();
    return dec.decode(decrypted);
  }
}

// SERVER SIDE
import * as crypto from 'crypto';

class ServerEncryptionService {
  // Server-side encryption for additional layer (optional)
  // Server uses a separate key stored in KMS
  static async encryptWithServerKey(
    plaintext: string,
    serverKey: Buffer
  ): Promise<{
    ciphertext: string;
    iv: string;
    tag: string;
  }> {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', serverKey, iv);
    
    let ciphertext = cipher.update(plaintext, 'utf8', 'base64');
    ciphertext += cipher.final('base64');
    const tag = cipher.getAuthTag();

    return {
      ciphertext,
      iv: iv.toString('base64'),
      tag: tag.toString('base64')
    };
  }

  static async decryptWithServerKey(
    ciphertext: string,
    serverKey: Buffer,
    iv: string,
    tag: string
  ): Promise<string> {
    const decipher = crypto.createDecipheriv(
      'aes-256-gcm',
      serverKey,
      Buffer.from(iv, 'base64')
    );
    
    decipher.setAuthTag(Buffer.from(tag, 'base64'));
    
    let plaintext = decipher.update(ciphertext, 'base64', 'utf8');
    plaintext += decipher.final('utf8');
    
    return plaintext;
  }
}
```

### 3.3 Double Encryption Strategy

Để tăng cường bảo mật, áp dụng **double encryption**:

1. **Layer 1 (Client)**: Encrypt với DEK (zero-knowledge)
2. **Layer 2 (Server)**: Encrypt ciphertext với Server Master Key từ KMS

```
Plaintext 
  → Client Encrypt (DEK) 
  → Ciphertext_1 
  → Server Encrypt (SMK) 
  → Ciphertext_2 
  → Store in MongoDB
```

**Lợi ích:**
- Nếu database bị breach, hacker cần cả SMK và DEK
- Server không thể decrypt về plaintext (thiếu DEK)
- Client không biết SMK

## 4. QUẢN LÝ KHÓA MÃ HÓA (KEY MANAGEMENT)

### 4.1 Key Hierarchy & Storage

```
┌─────────────────────────────────────────────────────┐
│            MASTER KEY (KMS)                          │
│  - Stored in AWS KMS / Azure Key Vault              │
│  - Never exposed to application code                │
│  - Used to encrypt DEKs before storage              │
│  - Supports automatic rotation                      │
└─────────────────────────────────────────────────────┘
                    ↓ Encrypts
┌─────────────────────────────────────────────────────┐
│        DATA ENCRYPTION KEYS (DEK)                    │
│  - Unique per user                                   │
│  - Encrypted by Master Key                          │
│  - Stored in MongoDB                                │
│  - Used to encrypt vault items                      │
└─────────────────────────────────────────────────────┘
                    ↓ Encrypts
┌─────────────────────────────────────────────────────┐
│           VAULT ITEMS (Passwords)                    │
│  - Stored in MongoDB as ciphertext                  │
└─────────────────────────────────────────────────────┘
```

### 4.2 Key Generation

```typescript
// Server-side key generation
import * as crypto from 'crypto';

interface KeyMetadata {
  keyId: string;
  version: number;
  algorithm: string;
  createdAt: Date;
  status: 'active' | 'rotated' | 'revoked';
}

class KeyManagementService {
  // Generate new encryption key
  static generateKey(bits: number = 256): Buffer {
    return crypto.randomBytes(bits / 8);
  }

  // Generate key with metadata
  static async createNewKey(): Promise<{
    key: Buffer;
    metadata: KeyMetadata;
  }> {
    const key = this.generateKey(256);
    const keyId = crypto.randomUUID();
    
    const metadata: KeyMetadata = {
      keyId,
      version: 1,
      algorithm: 'AES-256-GCM',
      createdAt: new Date(),
      status: 'active'
    };

    // Encrypt key with KMS master key before storage
    const encryptedKey = await this.encryptWithKMS(key);
    
    // Store in database
    await KeyRepository.create({
      keyId,
      encryptedKey: encryptedKey.toString('base64'),
      metadata
    });

    return { key, metadata };
  }

  // Integrate with AWS KMS
  static async encryptWithKMS(plainKey: Buffer): Promise<Buffer> {
    const AWS = require('aws-sdk');
    const kms = new AWS.KMS({ region: process.env.AWS_REGION });
    
    const params = {
      KeyId: process.env.KMS_KEY_ID,
      Plaintext: plainKey
    };
    
    const result = await kms.encrypt(params).promise();
    return result.CiphertextBlob;
  }

  static async decryptWithKMS(encryptedKey: Buffer): Promise<Buffer> {
    const AWS = require('aws-sdk');
    const kms = new AWS.KMS({ region: process.env.AWS_REGION });
    
    const params = {
      CiphertextBlob: encryptedKey
    };
    
    const result = await kms.decrypt(params).promise();
    return result.Plaintext;
  }
}
```

### 4.3 Key Rotation Strategy

**Tại sao cần Key Rotation?**
- Giảm rủi ro khi key bị compromise
- Tuân thủ compliance (PCI DSS, HIPAA, GDPR)
- Best practice bảo mật

**Quy trình Rotation:**

```typescript
class KeyRotationService {
  // Rotate master key (từ KMS)
  static async rotateMasterKey(): Promise<void> {
    // 1. Generate new master key in KMS
    const newMasterKeyId = await this.createNewKMSKey();
    
    // 2. Re-encrypt all DEKs with new master key
    const users = await UserRepository.findAll();
    
    for (const user of users) {
      // Decrypt DEK với old master key
      const oldDEK = await this.decryptWithKMS(
        user.encryptedDEK, 
        process.env.OLD_KMS_KEY_ID
      );
      
      // Re-encrypt với new master key
      const newEncryptedDEK = await this.encryptWithKMS(
        oldDEK, 
        newMasterKeyId
      );
      
      // Update database
      await UserRepository.update(user.id, {
        encryptedDEK: newEncryptedDEK.toString('base64'),
        keyVersion: user.keyVersion + 1,
        lastKeyRotation: new Date()
      });
    }
    
    // 3. Update environment variable
    await this.updateKMSKeyIdInConfig(newMasterKeyId);
    
    // 4. Schedule old key for deletion (30 days grace period)
    await this.scheduleKeyDeletion(process.env.OLD_KMS_KEY_ID, 30);
    
    // 5. Log rotation event
    await AuditService.log({
      event: 'KEY_ROTATION',
      severity: 'HIGH',
      details: { oldKeyId: process.env.OLD_KMS_KEY_ID, newKeyId: newMasterKeyId }
    });
  }

  // Rotate individual user's DEK
  static async rotateUserDEK(userId: string): Promise<void> {
    const user = await UserRepository.findById(userId);
    
    // Generate new DEK
    const newDEK = KeyManagementService.generateKey(256);
    
    // Get old DEK (user must be authenticated and provide EK)
    const oldDEK = await this.getUserDEK(userId);
    
    // Re-encrypt all vault items with new DEK
    const vaultItems = await VaultItemRepository.findByUserId(userId);
    
    for (const item of vaultItems) {
      // Decrypt với old DEK
      const plaintext = await EncryptionService.decrypt(
        item.ciphertext,
        oldDEK,
        item.iv
      );
      
      // Encrypt với new DEK
      const encrypted = await EncryptionService.encrypt(plaintext, newDEK);
      
      // Update database
      await VaultItemRepository.update(item.id, {
        ciphertext: encrypted.ciphertext,
        iv: encrypted.iv
      });
    }
    
    // Encrypt new DEK with user's EK (client must do this)
    // Send new encrypted DEK back to client to store
  }
}
```

### 4.4 Key Revocation

```typescript
class KeyRevocationService {
  // Revoke key khi phát hiện breach
  static async revokeKey(keyId: string, reason: string): Promise<void> {
    // 1. Mark key as revoked
    await KeyRepository.updateStatus(keyId, 'revoked');
    
    // 2. Log security event
    await AuditService.log({
      event: 'KEY_REVOKED',
      severity: 'CRITICAL',
      details: { keyId, reason, timestamp: new Date() }
    });
    
    // 3. Notify administrators
    await NotificationService.alertAdmins({
      subject: 'CRITICAL: Encryption Key Revoked',
      body: `Key ${keyId} has been revoked. Reason: ${reason}`
    });
    
    // 4. Force key rotation for affected users
    const affectedUsers = await this.findUsersWithKey(keyId);
    for (const user of affectedUsers) {
      await this.forceKeyRotationForUser(user.id);
      
      // Notify user
      await NotificationService.sendEmail(user.email, {
        subject: 'Security Alert: Your encryption key has been rotated',
        body: 'For your security, we have rotated your encryption key...'
      });
    }
    
    // 5. Disable key in KMS
    await this.disableKMSKey(keyId);
  }
}
```

### 4.5 Best Practices

1. **Never Hard-code Keys**
```typescript
// ❌ BAD
const SECRET_KEY = "my-secret-key-12345";

// ✅ GOOD
const SECRET_KEY = process.env.ENCRYPTION_KEY;
if (!SECRET_KEY) {
  throw new Error('ENCRYPTION_KEY not configured');
}
```

2. **Use Environment-specific Keys**
```
# .env.development
KMS_KEY_ID=alias/dev-master-key

# .env.production
KMS_KEY_ID=alias/prod-master-key
```

3. **Implement Key Versioning**
```typescript
interface EncryptedData {
  ciphertext: string;
  iv: string;
  keyVersion: number; // Track which key version encrypted this
  algorithm: string;
}
```

4. **Automate Key Rotation**
```typescript
// Schedule automatic rotation every 90 days
import * as cron from 'node-cron';

cron.schedule('0 0 1 */3 *', async () => {
  console.log('Starting scheduled key rotation...');
  await KeyRotationService.rotateMasterKey();
});
```

## 5. HỆ THỐNG OTP

### 5.1 OTP để Mở Khóa Vault

#### Use Cases:
- Đăng nhập từ thiết bị mới
- Thao tác nhạy cảm (xem/copy password, export vault)
- Thay đổi master password
- Xóa tài khoản

#### Implementation:

```typescript
import * as crypto from 'crypto';
import * as speakeasy from 'speakeasy';

interface OTPSession {
  id: string;
  userId: string;
  code: string; // Hashed
  purpose: 'login' | 'unlock' | 'sensitive_operation' | 'password_change';
  expiresAt: Date;
  attempts: number;
  maxAttempts: number;
  verified: boolean;
  ipAddress: string;
  userAgent: string;
}

class OTPService {
  private static readonly OTP_LENGTH = 6;
  private static readonly OTP_EXPIRY_MINUTES = 5;
  private static readonly MAX_ATTEMPTS = 3;

  // Generate OTP code
  static generateOTP(): string {
    const otp = crypto.randomInt(100000, 999999).toString();
    return otp;
  }

  // Create OTP session
  static async createOTPSession(
    userId: string,
    purpose: OTPSession['purpose'],
    metadata: { ipAddress: string; userAgent: string }
  ): Promise<{ sessionId: string; otp: string }> {
    const otp = this.generateOTP();
    const hashedOTP = await this.hashOTP(otp);
    
    const session: OTPSession = {
      id: crypto.randomUUID(),
      userId,
      code: hashedOTP,
      purpose,
      expiresAt: new Date(Date.now() + this.OTP_EXPIRY_MINUTES * 60 * 1000),
      attempts: 0,
      maxAttempts: this.MAX_ATTEMPTS,
      verified: false,
      ipAddress: metadata.ipAddress,
      userAgent: metadata.userAgent
    };

    await OTPRepository.create(session);
    
    // Log OTP generation
    await AuditService.log({
      event: 'OTP_GENERATED',
      userId,
      purpose,
      sessionId: session.id,
      ipAddress: metadata.ipAddress
    });

    return { sessionId: session.id, otp };
  }

  // Hash OTP before storage
  private static async hashOTP(otp: string): Promise<string> {
    const argon2 = require('argon2');
    return await argon2.hash(otp);
  }

  // Verify OTP
  static async verifyOTP(
    sessionId: string,
    otpCode: string,
    metadata: { ipAddress: string }
  ): Promise<{ success: boolean; message: string; session?: OTPSession }> {
    const session = await OTPRepository.findById(sessionId);

    if (!session) {
      await AuditService.log({
        event: 'OTP_VERIFICATION_FAILED',
        reason: 'SESSION_NOT_FOUND',
        sessionId,
        ipAddress: metadata.ipAddress
      });
      return { success: false, message: 'Invalid OTP session' };
    }

    // Check if already verified
    if (session.verified) {
      return { success: false, message: 'OTP already used' };
    }

    // Check expiration
    if (new Date() > session.expiresAt) {
      await OTPRepository.markAsExpired(sessionId);
      await AuditService.log({
        event: 'OTP_EXPIRED',
        sessionId,
        userId: session.userId
      });
      return { success: false, message: 'OTP expired' };
    }

    // Check attempts
    if (session.attempts >= session.maxAttempts) {
      await OTPRepository.markAsLocked(sessionId);
      await AuditService.log({
        event: 'OTP_MAX_ATTEMPTS_REACHED',
        sessionId,
        userId: session.userId,
        severity: 'HIGH'
      });
      return { success: false, message: 'Maximum attempts exceeded' };
    }

    // Increment attempts
    await OTPRepository.incrementAttempts(sessionId);

    // Verify OTP
    const argon2 = require('argon2');
    const isValid = await argon2.verify(session.code, otpCode);

    if (!isValid) {
      await AuditService.log({
        event: 'OTP_VERIFICATION_FAILED',
        reason: 'INVALID_CODE',
        sessionId,
        userId: session.userId,
        attempts: session.attempts + 1
      });
      return { 
        success: false, 
        message: `Invalid OTP. ${session.maxAttempts - session.attempts - 1} attempts remaining` 
      };
    }

    // Mark as verified
    await OTPRepository.markAsVerified(sessionId);
    
    await AuditService.log({
      event: 'OTP_VERIFIED',
      sessionId,
      userId: session.userId,
      purpose: session.purpose
    });

    return { success: true, message: 'OTP verified', session };
  }

  // Send OTP via email
  static async sendOTPEmail(
    email: string,
    otp: string,
    purpose: string
  ): Promise<void> {
    const emailService = new EmailService();
    
    await emailService.send({
      to: email,
      subject: `Your OTP Code for ${purpose}`,
      html: `
        <h2>Your One-Time Password</h2>
        <p>Your OTP code is: <strong style="font-size: 24px;">${otp}</strong></p>
        <p>This code will expire in ${this.OTP_EXPIRY_MINUTES} minutes.</p>
        <p>If you didn't request this code, please ignore this email.</p>
      `
    });
  }

  // Send OTP via SMS
  static async sendOTPSMS(
    phoneNumber: string,
    otp: string
  ): Promise<void> {
    const smsService = new SMSService();
    
    await smsService.send({
      to: phoneNumber,
      message: `Your OTP code is: ${otp}. Valid for ${this.OTP_EXPIRY_MINUTES} minutes.`
    });
  }

  // Cleanup expired OTP sessions
  static async cleanupExpiredSessions(): Promise<void> {
    await OTPRepository.deleteExpired();
  }
}
```

### 5.2 TOTP cho External Services (Gmail, etc.)

Cho phép người dùng lưu trữ **2FA secrets** của các dịch vụ bên ngoài.

```typescript
import * as speakeasy from 'speakeasy';
import * as QRCode from 'qrcode';

interface ExternalOTPSecret {
  id: string;
  userId: string;
  serviceName: string; // 'Gmail', 'GitHub', 'AWS', etc.
  encryptedSecret: string; // TOTP secret encrypted with DEK
  iv: string;
  accountIdentifier: string; // email/username for this service
  createdAt: Date;
  lastUsed?: Date;
}

class ExternalOTPService {
  // Save external 2FA secret
  static async saveExternalSecret(
    userId: string,
    serviceName: string,
    totpSecret: string,
    accountIdentifier: string,
    dek: string // Data Encryption Key from client
  ): Promise<string> {
    // Encrypt TOTP secret with user's DEK
    const encrypted = await EncryptionService.encrypt(totpSecret, dek);
    
    const record: ExternalOTPSecret = {
      id: crypto.randomUUID(),
      userId,
      serviceName,
      encryptedSecret: encrypted.ciphertext,
      iv: encrypted.iv,
      accountIdentifier,
      createdAt: new Date()
    };

    await ExternalOTPRepository.create(record);
    
    await AuditService.log({
      event: 'EXTERNAL_OTP_SAVED',
      userId,
      serviceName
    });

    return record.id;
  }

  // Get and decrypt external secret
  static async getExternalSecret(
    userId: string,
    secretId: string,
    dek: string
  ): Promise<string> {
    const record = await ExternalOTPRepository.findById(secretId);
    
    if (record.userId !== userId) {
      throw new Error('Unauthorized access');
    }

    // Decrypt secret
    const secret = await EncryptionService.decrypt(
      record.encryptedSecret,
      dek,
      record.iv
    );

    // Update last used
    await ExternalOTPRepository.updateLastUsed(secretId);

    return secret;
  }

  // Generate current TOTP code
  static generateTOTP(secret: string): string {
    return speakeasy.totp({
      secret: secret,
      encoding: 'base32'
    });
  }

  // Verify TOTP code
  static verifyTOTP(secret: string, token: string): boolean {
    return speakeasy.totp.verify({
      secret: secret,
      encoding: 'base32',
      token: token,
      window: 2 // Allow 2 time steps before/after
    });
  }

  // Generate QR code for setup
  static async generateQRCode(
    secret: string,
    serviceName: string,
    accountIdentifier: string
  ): Promise<string> {
    const otpauth = speakeasy.otpauthURL({
      secret: secret,
      label: `${serviceName}:${accountIdentifier}`,
      issuer: serviceName,
      encoding: 'base32'
    });

    const qrCodeDataURL = await QRCode.toDataURL(otpauth);
    return qrCodeDataURL;
  }

  // List all external OTP services for user
  static async listUserServices(userId: string): Promise<Array<{
    id: string;
    serviceName: string;
    accountIdentifier: string;
    createdAt: Date;
    lastUsed?: Date;
  }>> {
    const records = await ExternalOTPRepository.findByUserId(userId);
    
    return records.map(r => ({
      id: r.id,
      serviceName: r.serviceName,
      accountIdentifier: r.accountIdentifier,
      createdAt: r.createdAt,
      lastUsed: r.lastUsed
    }));
  }
}
```

### 5.3 OTP Flow Sequence

```
USER ACTION: Copy password from vault
    ↓
1. Frontend detect sensitive action
    ↓
2. Request OTP:
   POST /api/otp/request
   {
     purpose: "copy_password",
     itemId: "vault-item-123"
   }
    ↓
3. Backend generates OTP, sends email/SMS
   Returns: { sessionId: "xxx" }
    ↓
4. User receives OTP code
    ↓
5. User enters OTP in modal
    ↓
6. Frontend verifies OTP:
   POST /api/otp/verify
   {
     sessionId: "xxx",
     code: "123456"
   }
    ↓
7. Backend verifies OTP
   Returns: { verified: true, token: "short-lived-token" }
    ↓
8. Frontend uses token to perform action:
   POST /api/vault/items/123/decrypt
   Header: X-OTP-Token: short-lived-token
    ↓
9. Backend validates token, returns encrypted data
    ↓
10. Frontend decrypts with DEK, copies to clipboard
```

## 6. BẢO MẬT ĐẦU VÀO (INPUT VALIDATION)

### 6.1 Defense Strategy

```typescript
// Layered validation approach
Client Validation (UX)
    ↓
API Gateway Validation (Basic checks)
    ↓
Controller Validation (Schema validation)
    ↓
Service Layer Validation (Business logic)
    ↓
Database Validation (Schema constraints)
```

### 6.2 Schema Validation với Zod

```typescript
import { z } from 'zod';

// User registration schema
export const RegisterSchema = z.object({
  email: z.string()
    .email('Invalid email format')
    .max(255, 'Email too long')
    .transform(val => val.toLowerCase().trim()),
  
  authKeyHash: z.string()
    .length(128, 'Invalid auth key hash')
    .regex(/^[a-f0-9]+$/, 'Invalid hash format'),
  
  salt: z.string()
    .length(44, 'Invalid salt length') // Base64 of 32 bytes
    .regex(/^[A-Za-z0-9+/=]+$/, 'Invalid base64 format'),
  
  encryptedDEK: z.string()
    .min(44, 'Invalid encrypted DEK')
    .regex(/^[A-Za-z0-9+/=]+$/, 'Invalid base64 format'),
  
  dekIV: z.string()
    .length(16, 'Invalid IV length')
    .regex(/^[A-Za-z0-9+/=]+$/, 'Invalid base64 format')
});

// Vault item schema
export const VaultItemSchema = z.object({
  title: z.string()
    .min(1, 'Title required')
    .max(100, 'Title too long')
    .transform(val => val.trim()),
  
  encryptedData: z.string()
    .min(1, 'Data required')
    .max(10000, 'Data too large'), // Limit size
  
  iv: z.string()
    .length(16, 'Invalid IV length')
    .regex(/^[A-Za-z0-9+/=]+$/, 'Invalid base64 format'),
  
  category: z.enum(['password', 'note', 'card', 'identity']),
  
  metadata: z.object({
    website: z.string().url().optional(),
    username: z.string().max(255).optional(),
    tags: z.array(z.string().max(50)).max(10).optional()
  }).optional()
});

// OTP verification schema
export const OTPVerifySchema = z.object({
  sessionId: z.string().uuid('Invalid session ID'),
  code: z.string()
    .length(6, 'OTP must be 6 digits')
    .regex(/^\d{6}$/, 'OTP must contain only digits')
});
```

### 6.3 Validation Middleware

```typescript
import { Request, Response, NextFunction } from 'express';
import { ZodSchema, ZodError } from 'zod';

// Generic validation middleware
export const validateRequest = (schema: ZodSchema) => {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      // Validate and transform request body
      req.body = await schema.parseAsync(req.body);
      next();
    } catch (error) {
      if (error instanceof ZodError) {
        return res.status(400).json({
          error: 'Validation failed',
          details: error.errors.map(err => ({
            field: err.path.join('.'),
            message: err.message
          }))
        });
      }
      next(error);
    }
  };
};

// Sanitization middleware
import * as mongoSanitize from 'express-mongo-sanitize';
import * as xss from 'xss-clean';

export const sanitizationMiddleware = [
  // Remove $ and . from request body to prevent NoSQL injection
  mongoSanitize(),
  
  // Clean XSS attacks
  xss()
];
```

### 6.4 Anti-Injection Protection

#### A. NoSQL Injection Prevention

```typescript
// ❌ VULNERABLE
const user = await User.findOne({ 
  email: req.body.email // If email = {"$ne": null}, returns any user!
});

// ✅ SAFE
import { z } from 'zod';

const EmailSchema = z.string().email();
const email = EmailSchema.parse(req.body.email); // Throws if not string

const user = await User.findOne({ email });

// Additional: Use parameterized queries
const user = await User.findOne().where('email').equals(email);
```

#### B. XSS Prevention

```typescript
// Content Security Policy
import helmet from 'helmet';

app.use(helmet.contentSecurityPolicy({
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'"],
    styleSrc: ["'self'", "'unsafe-inline'"], // For Tailwind
    imgSrc: ["'self'", "data:", "https:"],
    connectSrc: ["'self'"],
    fontSrc: ["'self'"],
    objectSrc: ["'none'"],
    mediaSrc: ["'none'"],
    frameSrc: ["'none'"],
  }
}));

// Output encoding
import * as DOMPurify from 'isomorphic-dompurify';

function sanitizeHTML(dirty: string): string {
  return DOMPurify.sanitize(dirty, {
    ALLOWED_TAGS: [], // No HTML tags allowed
    ALLOWED_ATTR: []
  });
}

// In React components
import DOMPurify from 'dompurify';

function DisplayNote({ note }: { note: string }) {
  const clean = DOMPurify.sanitize(note);
  return <div dangerouslySetInnerHTML={{ __html: clean }} />;
}
```

#### C. Command Injection Prevention

```typescript
// ❌ VULNERABLE
import { exec } from 'child_process';
exec(`backup-db --user ${req.body.username}`); // NEVER DO THIS!

// ✅ SAFE - Avoid shell commands entirely
// Use libraries instead of shell commands
import * as fs from 'fs/promises';
import * as path from 'path';

async function backupData(userId: string) {
  // Validate userId
  const UUIDSchema = z.string().uuid();
  userId = UUIDSchema.parse(userId);
  
  // Use safe file operations
  const backupPath = path.join(
    '/safe/backup/directory',
    `${userId}.json`
  );
  
  // Ensure path doesn't escape directory
  if (!backupPath.startsWith('/safe/backup/directory')) {
    throw new Error('Invalid path');
  }
  
  const data = await getUserData(userId);
  await fs.writeFile(backupPath, JSON.stringify(data));
}
```

### 6.5 Rate Limiting

```typescript
import rateLimit from 'express-rate-limit';
import RedisStore from 'rate-limit-redis';
import Redis from 'ioredis';

const redis = new Redis(process.env.REDIS_URL);

// General API rate limit
export const generalLimiter = rateLimit({
  store: new RedisStore({
    client: redis,
    prefix: 'rl:general:'
  }),
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // 100 requests per window
  message: 'Too many requests, please try again later',
  standardHeaders: true,
  legacyHeaders: false
});

// Strict rate limit for authentication
export const authLimiter = rateLimit({
  store: new RedisStore({
    client: redis,
    prefix: 'rl:auth:'
  }),
  windowMs: 15 * 60 * 1000,
  max: 5, // Only 5 login attempts per 15 minutes
  message: 'Too many login attempts, please try again after 15 minutes',
  skipSuccessfulRequests: true // Don't count successful logins
});

// OTP rate limit
export const otpLimiter = rateLimit({
  store: new RedisStore({
    client: redis,
    prefix: 'rl:otp:'
  }),
  windowMs: 5 * 60 * 1000, // 5 minutes
  max: 3, // Max 3 OTP requests per 5 minutes
  message: 'Too many OTP requests'
});

// Apply to routes
app.post('/api/auth/login', authLimiter, authController.login);
app.post('/api/otp/request', otpLimiter, otpController.request);
app.use('/api', generalLimiter); // Apply to all API routes
```

### 6.6 Security Headers

```typescript
import helmet from 'helmet';

app.use(helmet({
  // Content Security Policy
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'none'"],
      frameSrc: ["'none'"]
    }
  },
  
  // HTTP Strict Transport Security
  hsts: {
    maxAge: 31536000, // 1 year
    includeSubDomains: true,
    preload: true
  },
  
  // Prevent clickjacking
  frameguard: {
    action: 'deny'
  },
  
  // Prevent MIME type sniffing
  noSniff: true,
  
  // XSS Protection
  xssFilter: true,
  
  // Hide X-Powered-By
  hidePoweredBy: true,
  
  // Referrer Policy
  referrerPolicy: {
    policy: 'strict-origin-when-cross-origin'
  }
}));

// CORS configuration
import cors from 'cors';

app.use(cors({
  origin: process.env.FRONTEND_URL,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-OTP-Token'],
  exposedHeaders: ['X-Request-ID'],
  maxAge: 600 // 10 minutes
}));
```

## 7. AUDIT LOGGING & MONITORING

```typescript
interface AuditLog {
  id: string;
  timestamp: Date;
  userId?: string;
  event: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  ipAddress: string;
  userAgent: string;
  details: Record<string, any>;
  success: boolean;
}

class AuditService {
  static async log(entry: Omit<AuditLog, 'id' | 'timestamp'>): Promise<void> {
    const log: AuditLog = {
      id: crypto.randomUUID(),
      timestamp: new Date(),
      ...entry
    };

    // Save to database
    await AuditLogRepository.create(log);
    
    // Send to monitoring service (e.g., DataDog, New Relic)
    if (entry.severity === 'CRITICAL') {
      await this.alertAdmins(log);
    }
  }

  private static async alertAdmins(log: AuditLog): Promise<void> {
    // Send alert via multiple channels
    await Promise.all([
      NotificationService.sendEmailToAdmins({
        subject: `CRITICAL Security Event: ${log.event}`,
        body: JSON.stringify(log, null, 2)
      }),
      NotificationService.sendSlackAlert({
        channel: '#security-alerts',
        message: `🚨 CRITICAL: ${log.event}`,
        details: log
      })
    ]);
  }
}

// Events to log:
// - LOGIN_SUCCESS / LOGIN_FAILED
// - PASSWORD_CHANGE
// - OTP_GENERATED / OTP_VERIFIED / OTP_FAILED
// - VAULT_ITEM_CREATED / UPDATED / DELETED / ACCESSED
// - KEY_ROTATION
// - SUSPICIOUS_ACTIVITY
// - ACCOUNT_LOCKED / UNLOCKED
// - EXPORT_VAULT
// - SETTINGS_CHANGED
```

Tài liệu này sẽ được tiếp tục với các phần còn lại...
