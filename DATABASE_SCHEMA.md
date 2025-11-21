# MongoDB Database Schema Design

## 1. COLLECTIONS OVERVIEW

```
password_manager_db/
├── users
├── vault_items
├── otp_sessions
├── audit_logs
├── encryption_keys
├── external_otp_secrets
├── sessions
└── device_trust
```

## 2. DETAILED SCHEMAS

### 2.1 Users Collection

```typescript
interface User {
  _id: ObjectId;
  email: string; // Unique index
  emailVerified: boolean;
  
  // Authentication (Zero-Knowledge)
  authKeyHash: string; // Argon2id hash of derived auth key
  salt: string; // For PBKDF2 derivation
  
  // Encrypted DEK (Data Encryption Key)
  encryptedDEK: string; // DEK encrypted with user's EK
  dekIV: string;
  dekAlgorithm: string; // "AES-256-GCM"
  keyVersion: number; // For key rotation tracking
  
  // Account security
  accountStatus: 'active' | 'locked' | 'suspended' | 'deleted';
  lockoutUntil?: Date;
  failedLoginAttempts: number;
  lastFailedLogin?: Date;
  
  // 2FA settings
  twoFactorEnabled: boolean;
  twoFactorMethod?: 'email' | 'sms' | 'totp';
  phoneNumber?: string; // For SMS OTP
  totpSecret?: string; // Encrypted TOTP secret
  backupCodes?: string[]; // Hashed backup codes
  
  // Profile
  displayName?: string;
  avatar?: string;
  
  // Security metadata
  passwordChangedAt?: Date;
  lastKeyRotation?: Date;
  
  // Timestamps
  createdAt: Date;
  updatedAt: Date;
  lastLoginAt?: Date;
  lastActivityAt?: Date;
  
  // Preferences
  preferences: {
    otpMethod: 'email' | 'sms';
    sessionTimeout: number; // minutes
    clipboardClearTime: number; // seconds
    requireOTPForCopy: boolean;
    requireOTPForExport: boolean;
  };
  
  // Indexes
  // - email: unique
  // - createdAt: 1
  // - accountStatus: 1
}
```

**MongoDB Indexes:**
```javascript
db.users.createIndex({ email: 1 }, { unique: true });
db.users.createIndex({ createdAt: 1 });
db.users.createIndex({ accountStatus: 1 });
db.users.createIndex({ lastActivityAt: 1 });
```

### 2.2 Vault Items Collection

```typescript
interface VaultItem {
  _id: ObjectId;
  userId: ObjectId; // Reference to users collection
  
  // Encrypted data
  encryptedData: string; // Password/note encrypted with user's DEK
  dataIV: string;
  authTag: string; // GCM authentication tag
  
  // Encrypted metadata
  encryptedMetadata: string; // Title, website, username encrypted
  metadataIV: string;
  
  // Item type and category
  itemType: 'password' | 'secure_note' | 'card' | 'identity' | 'external_otp';
  category?: string; // User-defined category
  
  // Search optimization (encrypted but searchable via client-side filtering)
  searchHash?: string; // Hash of title for quick filtering
  
  // Security
  favorite: boolean;
  
  // Usage tracking
  accessCount: number;
  lastAccessedAt?: Date;
  lastModifiedAt: Date;
  
  // Password-specific fields (encrypted in encryptedMetadata)
  // But we store type hints for UI
  strength?: 'weak' | 'medium' | 'strong' | 'very_strong';
  hasCompromiseWarning?: boolean;
  
  // Sharing (future feature)
  sharedWith?: ObjectId[];
  sharePermissions?: {
    userId: ObjectId;
    canView: boolean;
    canEdit: boolean;
    expiresAt?: Date;
  }[];
  
  // Soft delete
  deleted: boolean;
  deletedAt?: Date;
  
  // Timestamps
  createdAt: Date;
  updatedAt: Date;
  
  // Indexes
  // - userId: 1, deleted: 1, createdAt: -1
  // - userId: 1, itemType: 1
  // - userId: 1, category: 1
  // - userId: 1, favorite: 1
}
```

**MongoDB Indexes:**
```javascript
db.vault_items.createIndex({ userId: 1, deleted: 1, createdAt: -1 });
db.vault_items.createIndex({ userId: 1, itemType: 1 });
db.vault_items.createIndex({ userId: 1, category: 1 });
db.vault_items.createIndex({ userId: 1, favorite: 1 });
db.vault_items.createIndex({ userId: 1, lastAccessedAt: -1 });
```

### 2.3 OTP Sessions Collection

```typescript
interface OTPSession {
  _id: ObjectId;
  sessionId: string; // UUID, unique index
  userId: ObjectId;
  
  // OTP data
  codeHash: string; // Argon2id hash of OTP code
  purpose: 'login' | 'unlock_vault' | 'copy_password' | 'export_vault' 
           | 'change_password' | 'delete_account' | 'add_device';
  
  // Related resources
  resourceId?: string; // e.g., vaultItemId for copy_password
  
  // Security
  attempts: number;
  maxAttempts: number; // Usually 3
  verified: boolean;
  
  // Expiration
  createdAt: Date;
  expiresAt: Date;
  verifiedAt?: Date;
  
  // Request metadata
  ipAddress: string;
  userAgent: string;
  location?: {
    country?: string;
    city?: string;
  };
  
  // Status
  status: 'pending' | 'verified' | 'expired' | 'locked' | 'revoked';
  
  // Indexes
  // - sessionId: unique
  // - userId: 1, createdAt: -1
  // - expiresAt: 1 (TTL index)
  // - status: 1, expiresAt: 1
}
```

**MongoDB Indexes:**
```javascript
db.otp_sessions.createIndex({ sessionId: 1 }, { unique: true });
db.otp_sessions.createIndex({ userId: 1, createdAt: -1 });
db.otp_sessions.createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 }); // TTL index
db.otp_sessions.createIndex({ status: 1, expiresAt: 1 });
```

### 2.4 Audit Logs Collection

```typescript
interface AuditLog {
  _id: ObjectId;
  logId: string; // UUID for reference
  
  // User context
  userId?: ObjectId; // Optional (some events may not have user)
  sessionId?: string;
  
  // Event details
  event: string; // e.g., 'LOGIN_SUCCESS', 'PASSWORD_COPIED', 'OTP_FAILED'
  eventCategory: 'auth' | 'vault' | 'otp' | 'security' | 'admin' | 'system';
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  
  // Status
  success: boolean;
  errorMessage?: string;
  
  // Request metadata
  ipAddress: string;
  userAgent: string;
  location?: {
    country?: string;
    city?: string;
    coordinates?: [number, number]; // [longitude, latitude]
  };
  
  // Additional context
  resourceType?: string; // 'vault_item', 'user', 'key', etc.
  resourceId?: string;
  details?: Record<string, any>; // Flexible field for event-specific data
  
  // Changes (for update events)
  changes?: {
    before?: Record<string, any>;
    after?: Record<string, any>;
  };
  
  // Timestamps
  timestamp: Date;
  
  // Retention policy
  expiresAt?: Date; // For automatic cleanup
  
  // Indexes
  // - userId: 1, timestamp: -1
  // - event: 1, timestamp: -1
  // - severity: 1, timestamp: -1
  // - eventCategory: 1, timestamp: -1
  // - timestamp: -1
  // - expiresAt: 1 (TTL index)
}
```

**MongoDB Indexes:**
```javascript
db.audit_logs.createIndex({ userId: 1, timestamp: -1 });
db.audit_logs.createIndex({ event: 1, timestamp: -1 });
db.audit_logs.createIndex({ severity: 1, timestamp: -1 });
db.audit_logs.createIndex({ eventCategory: 1, timestamp: -1 });
db.audit_logs.createIndex({ timestamp: -1 });
db.audit_logs.createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 }); // Auto-delete old logs
```

### 2.5 Encryption Keys Collection

```typescript
interface EncryptionKey {
  _id: ObjectId;
  keyId: string; // UUID, unique
  
  // Key data (encrypted by KMS)
  encryptedKey: string; // Key encrypted by KMS master key
  kmsKeyId: string; // Reference to KMS key used
  
  // Key metadata
  algorithm: string; // e.g., "AES-256-GCM"
  keySize: number; // 256
  version: number;
  
  // Key status
  status: 'active' | 'rotated' | 'revoked' | 'scheduled_deletion';
  
  // Usage
  purpose: 'dek_encryption' | 'backup_encryption' | 'export_encryption';
  usedBy?: 'all_users' | 'specific_users';
  userIds?: ObjectId[]; // If specific users
  
  // Lifecycle
  createdAt: Date;
  activatedAt?: Date;
  rotatedAt?: Date;
  revokedAt?: Date;
  scheduledDeletionAt?: Date;
  
  // Rotation tracking
  previousKeyId?: string; // Reference to previous key version
  nextKeyId?: string; // Reference to next key version
  
  // Indexes
  // - keyId: unique
  // - status: 1, createdAt: -1
  // - kmsKeyId: 1
}
```

**MongoDB Indexes:**
```javascript
db.encryption_keys.createIndex({ keyId: 1 }, { unique: true });
db.encryption_keys.createIndex({ status: 1, createdAt: -1 });
db.encryption_keys.createIndex({ kmsKeyId: 1 });
```

### 2.6 External OTP Secrets Collection

```typescript
interface ExternalOTPSecret {
  _id: ObjectId;
  userId: ObjectId;
  
  // Service information
  serviceName: string; // "Gmail", "GitHub", "AWS", etc.
  serviceType: 'email' | 'cloud' | 'social' | 'finance' | 'other';
  accountIdentifier: string; // Email or username for that service
  
  // Encrypted TOTP secret
  encryptedSecret: string; // Encrypted with user's DEK
  secretIV: string;
  authTag: string;
  
  // OTP settings
  otpAlgorithm: 'SHA1' | 'SHA256' | 'SHA512'; // Usually SHA1
  otpDigits: number; // Usually 6
  otpPeriod: number; // Usually 30 seconds
  
  // Recovery codes (also encrypted)
  encryptedRecoveryCodes?: string[];
  recoveryCodesIV?: string;
  
  // Custom fields (encrypted)
  encryptedNotes?: string;
  notesIV?: string;
  
  // Icon/Logo
  iconUrl?: string;
  
  // Usage tracking
  lastUsedAt?: Date;
  useCount: number;
  
  // Organization
  category?: string;
  favorite: boolean;
  
  // Soft delete
  deleted: boolean;
  deletedAt?: Date;
  
  // Timestamps
  createdAt: Date;
  updatedAt: Date;
  
  // Indexes
  // - userId: 1, deleted: 1, createdAt: -1
  // - userId: 1, serviceName: 1
  // - userId: 1, favorite: 1
}
```

**MongoDB Indexes:**
```javascript
db.external_otp_secrets.createIndex({ userId: 1, deleted: 1, createdAt: -1 });
db.external_otp_secrets.createIndex({ userId: 1, serviceName: 1 });
db.external_otp_secrets.createIndex({ userId: 1, favorite: 1 });
```

### 2.7 Sessions Collection

```typescript
interface Session {
  _id: ObjectId;
  sessionToken: string; // JWT ID or session token, unique
  userId: ObjectId;
  
  // Session data
  refreshToken?: string; // Hashed
  
  // Device information
  deviceId?: string; // Unique device identifier
  deviceName?: string; // "Chrome on Windows"
  deviceType: 'desktop' | 'mobile' | 'tablet' | 'unknown';
  
  // Request metadata
  ipAddress: string;
  userAgent: string;
  location?: {
    country?: string;
    city?: string;
  };
  
  // Security
  trusted: boolean; // Trusted device
  mfaVerified: boolean; // MFA passed for this session
  
  // Lifecycle
  createdAt: Date;
  lastActivityAt: Date;
  expiresAt: Date;
  
  // Status
  status: 'active' | 'expired' | 'revoked';
  revokedAt?: Date;
  revokedReason?: string;
  
  // Indexes
  // - sessionToken: unique
  // - userId: 1, status: 1, lastActivityAt: -1
  // - expiresAt: 1 (TTL index)
}
```

**MongoDB Indexes:**
```javascript
db.sessions.createIndex({ sessionToken: 1 }, { unique: true });
db.sessions.createIndex({ userId: 1, status: 1, lastActivityAt: -1 });
db.sessions.createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 });
```

### 2.8 Device Trust Collection

```typescript
interface DeviceTrust {
  _id: ObjectId;
  userId: ObjectId;
  deviceId: string; // Unique device fingerprint
  
  // Device information
  deviceName: string;
  deviceType: 'desktop' | 'mobile' | 'tablet';
  platform: string; // "Windows", "macOS", "iOS", "Android"
  browser: string;
  
  // Trust status
  trusted: boolean;
  trustLevel: 'unknown' | 'recognized' | 'trusted';
  
  // Verification
  verifiedAt?: Date;
  verificationMethod?: 'otp' | 'email_link' | 'biometric';
  
  // First seen
  firstSeenAt: Date;
  firstSeenIP: string;
  firstSeenLocation?: {
    country?: string;
    city?: string;
  };
  
  // Last activity
  lastSeenAt: Date;
  lastSeenIP: string;
  lastSeenLocation?: {
    country?: string;
    city?: string;
  };
  
  // Security
  suspicious: boolean;
  suspicionReasons?: string[];
  blockedAt?: Date;
  
  // Indexes
  // - userId: 1, deviceId: 1 (unique compound)
  // - userId: 1, trusted: 1
  // - userId: 1, lastSeenAt: -1
}
```

**MongoDB Indexes:**
```javascript
db.device_trust.createIndex({ userId: 1, deviceId: 1 }, { unique: true });
db.device_trust.createIndex({ userId: 1, trusted: 1 });
db.device_trust.createIndex({ userId: 1, lastSeenAt: -1 });
```

## 3. SAMPLE MONGODB QUERIES

### 3.1 Create User
```javascript
db.users.insertOne({
  email: "user@example.com",
  emailVerified: true,
  authKeyHash: "...",
  salt: "...",
  encryptedDEK: "...",
  dekIV: "...",
  dekAlgorithm: "AES-256-GCM",
  keyVersion: 1,
  accountStatus: "active",
  failedLoginAttempts: 0,
  twoFactorEnabled: false,
  preferences: {
    otpMethod: "email",
    sessionTimeout: 30,
    clipboardClearTime: 30,
    requireOTPForCopy: true,
    requireOTPForExport: true
  },
  createdAt: new Date(),
  updatedAt: new Date()
});
```

### 3.2 Get User's Vault Items
```javascript
db.vault_items.find({
  userId: ObjectId("..."),
  deleted: false
}).sort({ createdAt: -1 }).limit(50);
```

### 3.3 Get Active OTP Sessions
```javascript
db.otp_sessions.find({
  userId: ObjectId("..."),
  status: "pending",
  expiresAt: { $gt: new Date() }
}).sort({ createdAt: -1 });
```

### 3.4 Get Recent Audit Logs
```javascript
db.audit_logs.find({
  userId: ObjectId("..."),
  timestamp: {
    $gte: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) // Last 7 days
  }
}).sort({ timestamp: -1 }).limit(100);
```

### 3.5 Find Suspicious Activity
```javascript
db.audit_logs.find({
  userId: ObjectId("..."),
  severity: { $in: ["HIGH", "CRITICAL"] },
  success: false,
  timestamp: {
    $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) // Last 24 hours
  }
});
```

### 3.6 Get User's External OTP Services
```javascript
db.external_otp_secrets.find({
  userId: ObjectId("..."),
  deleted: false
}).sort({ serviceName: 1 });
```

### 3.7 Clean Up Expired Sessions
```javascript
db.sessions.updateMany(
  {
    expiresAt: { $lt: new Date() },
    status: "active"
  },
  {
    $set: {
      status: "expired",
      revokedAt: new Date(),
      revokedReason: "expired"
    }
  }
);
```

## 4. DATA RETENTION POLICIES

### 4.1 Audit Logs
```javascript
// Keep audit logs for 90 days, then auto-delete
db.audit_logs.createIndex(
  { timestamp: 1 },
  { expireAfterSeconds: 90 * 24 * 60 * 60 } // 90 days
);
```

### 4.2 OTP Sessions
```javascript
// Auto-delete OTP sessions after expiration
db.otp_sessions.createIndex(
  { expiresAt: 1 },
  { expireAfterSeconds: 0 } // Delete immediately after expiration
);
```

### 4.3 Deleted Vault Items
```javascript
// Soft delete for 30 days, then hard delete
// Run this as a scheduled job
db.vault_items.deleteMany({
  deleted: true,
  deletedAt: {
    $lt: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) // 30 days ago
  }
});
```

## 5. BACKUP STRATEGY

```javascript
// Backup script example
const backupConfig = {
  // Full backup daily
  fullBackup: {
    schedule: "0 0 * * *", // Every day at midnight
    retention: 30, // Keep for 30 days
    collections: [
      "users",
      "vault_items",
      "external_otp_secrets",
      "encryption_keys"
    ]
  },
  
  // Incremental backup every 6 hours
  incrementalBackup: {
    schedule: "0 */6 * * *", // Every 6 hours
    retention: 7, // Keep for 7 days
    collections: [
      "vault_items",
      "audit_logs"
    ]
  }
};

// Backup command
// mongodump --uri="mongodb://..." --out=/backup/$(date +%Y%m%d_%H%M%S)
```

## 6. PERFORMANCE OPTIMIZATION

### 6.1 Query Optimization Tips

1. **Always use indexes for queries**
```javascript
// ❌ Bad - Full collection scan
db.vault_items.find({ userId: "..." });

// ✅ Good - Uses index
db.vault_items.find({ userId: ObjectId("..."), deleted: false });
```

2. **Use projection to reduce data transfer**
```javascript
// Only fetch needed fields
db.vault_items.find(
  { userId: ObjectId("..."), deleted: false },
  { encryptedData: 1, dataIV: 1, itemType: 1 }
);
```

3. **Use aggregation pipeline for complex queries**
```javascript
db.vault_items.aggregate([
  { $match: { userId: ObjectId("..."), deleted: false } },
  { $group: {
    _id: "$itemType",
    count: { $sum: 1 }
  }},
  { $sort: { count: -1 } }
]);
```

### 6.2 Connection Pooling

```typescript
import mongoose from 'mongoose';

mongoose.connect(process.env.MONGODB_URI, {
  maxPoolSize: 10, // Max 10 connections in pool
  minPoolSize: 2,  // Keep at least 2 connections
  socketTimeoutMS: 45000,
  serverSelectionTimeoutMS: 5000,
  family: 4 // Use IPv4
});
```

## 7. MONGODB SECURITY CONFIGURATION

```javascript
// Enable authentication
use admin
db.createUser({
  user: "adminUser",
  pwd: "strongPassword",
  roles: [ { role: "root", db: "admin" } ]
});

// Create application user with limited permissions
use password_manager_db
db.createUser({
  user: "appUser",
  pwd: "appPassword",
  roles: [
    { role: "readWrite", db: "password_manager_db" }
  ]
});

// Enable encryption at rest (MongoDB Enterprise)
// mongod --enableEncryption \
//   --encryptionKeyFile /path/to/keyfile \
//   --encryptionCipherMode AES256-GCM
```

## 8. MIGRATION SCRIPTS

### 8.1 Initial Setup Script

```typescript
// scripts/db-init.ts
import mongoose from 'mongoose';

async function initializeDatabase() {
  await mongoose.connect(process.env.MONGODB_URI);
  
  const db = mongoose.connection.db;
  
  // Create collections
  await db.createCollection('users');
  await db.createCollection('vault_items');
  await db.createCollection('otp_sessions');
  await db.createCollection('audit_logs');
  await db.createCollection('encryption_keys');
  await db.createCollection('external_otp_secrets');
  await db.createCollection('sessions');
  await db.createCollection('device_trust');
  
  // Create indexes
  await createIndexes(db);
  
  console.log('Database initialized successfully');
}

async function createIndexes(db: any) {
  // Users indexes
  await db.collection('users').createIndex({ email: 1 }, { unique: true });
  await db.collection('users').createIndex({ createdAt: 1 });
  
  // Vault items indexes
  await db.collection('vault_items').createIndex(
    { userId: 1, deleted: 1, createdAt: -1 }
  );
  
  // OTP sessions indexes
  await db.collection('otp_sessions').createIndex(
    { sessionId: 1 }, 
    { unique: true }
  );
  await db.collection('otp_sessions').createIndex(
    { expiresAt: 1 }, 
    { expireAfterSeconds: 0 }
  );
  
  // Audit logs indexes
  await db.collection('audit_logs').createIndex({ timestamp: -1 });
  await db.collection('audit_logs').createIndex(
    { userId: 1, timestamp: -1 }
  );
  
  // More indexes...
  console.log('Indexes created successfully');
}

initializeDatabase().catch(console.error);
```
