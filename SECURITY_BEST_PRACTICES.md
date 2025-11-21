# 🛡️ Security Best Practices & Guidelines

## 1. DEVELOPMENT SECURITY

### Code Security

#### A. Never Trust User Input

```typescript
// ❌ BAD - Vulnerable to injection
app.get('/user/:id', async (req, res) => {
  const user = await db.query(`SELECT * FROM users WHERE id = ${req.params.id}`);
});

// ✅ GOOD - Parameterized query
app.get('/user/:id', async (req, res) => {
  const userId = z.string().uuid().parse(req.params.id);
  const user = await User.findById(userId);
});
```

#### B. Validate Everything

```typescript
// ❌ BAD
const createUser = async (data: any) => {
  await User.create(data);
};

// ✅ GOOD
import { z } from 'zod';

const UserSchema = z.object({
  email: z.string().email().max(255),
  name: z.string().min(1).max(100),
  age: z.number().int().min(0).max(150)
});

const createUser = async (data: unknown) => {
  const validated = UserSchema.parse(data);
  await User.create(validated);
};
```

#### C. Secure Password Handling

```typescript
// ❌ BAD - Plaintext password
await User.create({
  email: 'user@example.com',
  password: 'password123'
});

// ❌ BAD - Weak hashing
const md5Hash = crypto.createHash('md5').update(password).digest('hex');

// ✅ GOOD - Argon2id (recommended)
import * as argon2 from 'argon2';

const hashedPassword = await argon2.hash(password, {
  type: argon2.argon2id,
  memoryCost: 65536,
  timeCost: 3,
  parallelism: 4
});

await User.create({
  email: 'user@example.com',
  password: hashedPassword
});
```

#### D. Secrets Management

```typescript
// ❌ BAD - Hard-coded secrets
const JWT_SECRET = 'my-secret-key-123';
const API_KEY = 'sk_live_abc123xyz';

// ❌ BAD - Committed to git
// .env file in repository

// ✅ GOOD - Environment variables
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  throw new Error('JWT_SECRET not configured');
}

// ✅ GOOD - AWS Secrets Manager
import AWS from 'aws-sdk';
const secretsManager = new AWS.SecretsManager();

async function getSecret(secretName: string): Promise<string> {
  const data = await secretsManager.getSecretValue({ SecretId: secretName }).promise();
  return data.SecretString!;
}
```

### Authentication & Authorization

#### A. JWT Best Practices

```typescript
// ✅ Strong JWT configuration
import jwt from 'jsonwebtoken';

const accessToken = jwt.sign(
  { 
    userId: user.id,
    email: user.email
    // DON'T include sensitive data
  },
  process.env.JWT_SECRET,
  {
    expiresIn: '15m', // Short expiry
    issuer: 'password-manager',
    audience: 'password-manager-api',
    algorithm: 'HS256'
  }
);

const refreshToken = jwt.sign(
  { userId: user.id, tokenType: 'refresh' },
  process.env.JWT_REFRESH_SECRET,
  {
    expiresIn: '7d',
    issuer: 'password-manager',
    audience: 'password-manager-api',
    algorithm: 'HS256'
  }
);
```

#### B. Secure Session Management

```typescript
// ✅ Session security
interface Session {
  userId: string;
  deviceId: string;
  ipAddress: string;
  userAgent: string;
  createdAt: Date;
  expiresAt: Date;
  lastActivityAt: Date;
}

// Implement session rotation
async function rotateSession(oldSessionId: string): Promise<string> {
  const oldSession = await Session.findById(oldSessionId);
  
  // Create new session
  const newSession = await Session.create({
    userId: oldSession.userId,
    deviceId: oldSession.deviceId,
    ipAddress: oldSession.ipAddress,
    userAgent: oldSession.userAgent,
    createdAt: new Date(),
    expiresAt: new Date(Date.now() + 30 * 60 * 1000)
  });
  
  // Invalidate old session
  await Session.delete(oldSessionId);
  
  return newSession.id;
}
```

#### C. Multi-Factor Authentication

```typescript
// ✅ Implement 2FA
class TwoFactorAuth {
  // TOTP (Time-based OTP)
  static async generateTOTPSecret(): Promise<{
    secret: string;
    qrCode: string;
  }> {
    const secret = speakeasy.generateSecret({
      name: 'Password Manager',
      length: 32
    });

    const qrCode = await QRCode.toDataURL(secret.otpauth_url!);

    return {
      secret: secret.base32,
      qrCode
    };
  }

  static verifyTOTP(token: string, secret: string): boolean {
    return speakeasy.totp.verify({
      secret,
      encoding: 'base32',
      token,
      window: 2 // Allow 2 time steps tolerance
    });
  }
}
```

### Data Protection

#### A. Encryption at Rest

```typescript
// ✅ Encrypt sensitive data before storage
class DataProtection {
  static async encryptSensitiveField(
    data: string,
    userId: string
  ): Promise<EncryptedData> {
    // Get user's encryption key
    const userKey = await this.getUserEncryptionKey(userId);
    
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', userKey, iv);
    
    let encrypted = cipher.update(data, 'utf8', 'base64');
    encrypted += cipher.final('base64');
    
    const authTag = cipher.getAuthTag();
    
    return {
      ciphertext: encrypted,
      iv: iv.toString('base64'),
      authTag: authTag.toString('base64')
    };
  }
}
```

#### B. Secure Data Deletion

```typescript
// ❌ BAD - Soft delete only
await Item.update({ id }, { deleted: true });

// ✅ GOOD - Secure deletion with overwrite
class SecureDeletion {
  static async secureDelete(itemId: string): Promise<void> {
    const item = await Item.findById(itemId);
    
    // 1. Overwrite sensitive data with random bytes
    await Item.update(itemId, {
      encryptedData: crypto.randomBytes(item.encryptedData.length).toString('base64'),
      metadata: crypto.randomBytes(100).toString('base64')
    });
    
    // 2. Mark as deleted
    await Item.update(itemId, { deleted: true, deletedAt: new Date() });
    
    // 3. Schedule permanent deletion after 30 days
    await ScheduledDeletion.create({
      itemId,
      scheduledFor: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000)
    });
    
    // 4. Log deletion
    await AuditLog.create({
      event: 'ITEM_DELETED',
      userId: item.userId,
      itemId,
      timestamp: new Date()
    });
  }
}
```

### API Security

#### A. Rate Limiting

```typescript
// ✅ Comprehensive rate limiting
import rateLimit from 'express-rate-limit';
import RedisStore from 'rate-limit-redis';

// General API limiter
const generalLimiter = rateLimit({
  store: new RedisStore({ client: redis }),
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    res.status(429).json({
      error: 'Too Many Requests',
      retryAfter: res.getHeader('Retry-After')
    });
  }
});

// Strict limiter for sensitive endpoints
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  skipSuccessfulRequests: true
});

// Progressive rate limiting (increases after failures)
class AdaptiveRateLimiter {
  static async checkAndIncrement(
    key: string,
    maxAttempts: number = 5
  ): Promise<boolean> {
    const attempts = await redis.incr(key);
    
    if (attempts === 1) {
      await redis.expire(key, 900); // 15 minutes
    }
    
    if (attempts > maxAttempts) {
      // Exponential backoff
      const backoffTime = Math.min(Math.pow(2, attempts - maxAttempts) * 60, 3600);
      await redis.expire(key, backoffTime);
      return false;
    }
    
    return true;
  }
}
```

#### B. CORS Configuration

```typescript
// ✅ Strict CORS policy
import cors from 'cors';

const corsOptions: cors.CorsOptions = {
  origin: (origin, callback) => {
    const whitelist = process.env.ALLOWED_ORIGINS?.split(',') || [];
    
    if (!origin || whitelist.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  exposedHeaders: ['X-Request-ID'],
  maxAge: 600,
  optionsSuccessStatus: 204
};

app.use(cors(corsOptions));
```

#### C. Security Headers

```typescript
// ✅ Comprehensive security headers
import helmet from 'helmet';

app.use(helmet({
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
      frameSrc: ["'none'"],
      baseUri: ["'self'"],
      formAction: ["'self'"],
      frameAncestors: ["'none'"],
      upgradeInsecureRequests: []
    }
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  },
  noSniff: true,
  xssFilter: true,
  hidePoweredBy: true,
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' }
}));
```

### Error Handling

```typescript
// ❌ BAD - Exposing sensitive information
app.use((err, req, res, next) => {
  res.json({
    error: err.message,
    stack: err.stack,
    query: req.query
  });
});

// ✅ GOOD - Generic error messages
app.use((err, req, res, next) => {
  // Log full error for debugging
  logger.error('Error:', {
    error: err.message,
    stack: err.stack,
    path: req.path,
    method: req.method,
    userId: req.user?.id
  });
  
  // Send generic error to client
  const statusCode = err.statusCode || 500;
  const message = statusCode === 500 
    ? 'Internal server error' 
    : err.message;
  
  res.status(statusCode).json({
    error: message,
    requestId: req.id
  });
});
```

## 2. PRODUCTION SECURITY

### Infrastructure Security

#### A. Network Security

```bash
# Firewall rules (UFW)
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp    # SSH (restrict to specific IPs)
sudo ufw allow 80/tcp    # HTTP (redirect to HTTPS)
sudo ufw allow 443/tcp   # HTTPS
sudo ufw enable

# Restrict MongoDB access
sudo ufw allow from 10.0.1.5 to any port 27017  # Only from app server

# Fail2Ban for brute force protection
sudo apt-get install fail2ban
sudo systemctl enable fail2ban
sudo systemctl start fail2ban
```

#### B. SSL/TLS Configuration

```nginx
# Nginx SSL best practices
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384';
ssl_prefer_server_ciphers off;

# OCSP Stapling
ssl_stapling on;
ssl_stapling_verify on;
ssl_trusted_certificate /path/to/chain.pem;

# Session Cache
ssl_session_cache shared:SSL:10m;
ssl_session_timeout 10m;
ssl_session_tickets off;

# HSTS
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
```

#### C. Database Security

```javascript
// MongoDB security configuration
// 1. Enable authentication
use admin
db.createUser({
  user: "adminUser",
  pwd: passwordPrompt(),
  roles: [ { role: "root", db: "admin" } ]
});

// 2. Create application user with minimal permissions
use password_manager_db
db.createUser({
  user: "appUser",
  pwd: passwordPrompt(),
  roles: [
    { role: "readWrite", db: "password_manager_db" }
  ]
});

// 3. Enable encryption at rest (MongoDB Enterprise)
mongod --enableEncryption \
  --encryptionKeyFile /path/to/keyfile \
  --encryptionCipherMode AES256-GCM

// 4. Enable audit logging
mongod --auditDestination file \
  --auditFormat JSON \
  --auditPath /var/log/mongodb/audit.json
```

### Monitoring & Alerting

#### A. Security Monitoring

```typescript
// Real-time security monitoring
class SecurityMonitor {
  private static readonly ALERT_THRESHOLDS = {
    failedLogins: 5,
    suspiciousActivity: 3,
    dataExfiltration: 100 // MB
  };

  static async monitorFailedLogins(userId: string): Promise<void> {
    const key = `failed_logins:${userId}`;
    const count = await redis.incr(key);
    
    if (count === 1) {
      await redis.expire(key, 3600); // 1 hour window
    }
    
    if (count >= this.ALERT_THRESHOLDS.failedLogins) {
      await this.sendSecurityAlert({
        type: 'EXCESSIVE_FAILED_LOGINS',
        userId,
        count,
        severity: 'HIGH'
      });
      
      // Lock account temporarily
      await User.update(userId, {
        accountStatus: 'locked',
        lockoutUntil: new Date(Date.now() + 30 * 60 * 1000)
      });
    }
  }

  static async detectAnomalousActivity(
    userId: string,
    activity: ActivityLog
  ): Promise<void> {
    // Check for unusual patterns
    const recentActivities = await ActivityLog.find({
      userId,
      timestamp: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) }
    });

    // Different location
    if (this.isDifferentLocation(activity, recentActivities)) {
      await this.sendSecurityAlert({
        type: 'LOCATION_CHANGE',
        userId,
        newLocation: activity.location,
        severity: 'MEDIUM'
      });
    }

    // Different device
    if (this.isNewDevice(activity, recentActivities)) {
      // Require OTP verification
      await OTPService.createSession(userId, 'verify_device');
    }

    // Unusual time
    if (this.isUnusualTime(activity, recentActivities)) {
      await this.sendSecurityAlert({
        type: 'UNUSUAL_ACCESS_TIME',
        userId,
        time: activity.timestamp,
        severity: 'LOW'
      });
    }
  }

  private static async sendSecurityAlert(alert: SecurityAlert): Promise<void> {
    // Log to database
    await SecurityAlert.create(alert);
    
    // Send email
    if (alert.severity === 'HIGH' || alert.severity === 'CRITICAL') {
      await EmailService.send({
        to: await this.getUserEmail(alert.userId),
        subject: `Security Alert: ${alert.type}`,
        template: 'security-alert',
        data: alert
      });
    }
    
    // Send to monitoring service
    await MonitoringService.track('security.alert', {
      ...alert,
      timestamp: new Date()
    });
  }
}
```

#### B. Audit Logging

```typescript
// Comprehensive audit logging
class AuditLogger {
  static async log(entry: {
    userId?: string;
    action: string;
    resource: string;
    resourceId?: string;
    changes?: any;
    metadata?: any;
    ip: string;
    userAgent: string;
  }): Promise<void> {
    await AuditLog.create({
      ...entry,
      timestamp: new Date(),
      requestId: crypto.randomUUID()
    });

    // Additional checks for sensitive operations
    if (this.isSensitiveOperation(entry.action)) {
      await this.notifySecurity(entry);
    }
  }

  private static isSensitiveOperation(action: string): boolean {
    const sensitive = [
      'PASSWORD_CHANGED',
      'ACCOUNT_DELETED',
      'VAULT_EXPORTED',
      'ENCRYPTION_KEY_ACCESSED',
      'ADMIN_ACTION'
    ];
    return sensitive.includes(action);
  }

  // Query audit logs
  static async queryLogs(filters: {
    userId?: string;
    action?: string;
    startDate?: Date;
    endDate?: Date;
    severity?: string;
  }): Promise<AuditLog[]> {
    return await AuditLog.find(filters)
      .sort({ timestamp: -1 })
      .limit(1000);
  }
}
```

### Incident Response

#### A. Security Incident Playbook

```typescript
class IncidentResponse {
  static async handleSecurityBreach(incident: {
    type: 'data_breach' | 'unauthorized_access' | 'ddos' | 'malware';
    severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    description: string;
  }): Promise<void> {
    // 1. Log incident
    await SecurityIncident.create({
      ...incident,
      timestamp: new Date(),
      status: 'investigating'
    });

    // 2. Alert security team
    await this.alertSecurityTeam(incident);

    // 3. Take immediate action based on severity
    if (incident.severity === 'CRITICAL') {
      // Enable maintenance mode
      await this.enableMaintenanceMode();
      
      // Revoke all active sessions
      await Session.updateMany({}, { status: 'revoked' });
      
      // Rotate encryption keys
      await KeyManagementService.emergencyKeyRotation();
    }

    // 4. Collect evidence
    await this.collectForensicData();

    // 5. Notify affected users (if data breach)
    if (incident.type === 'data_breach') {
      await this.notifyAffectedUsers();
    }

    // 6. Document incident
    await this.generateIncidentReport(incident);
  }

  private static async collectForensicData(): Promise<void> {
    // Capture current state
    const evidence = {
      activeSessions: await Session.find({ status: 'active' }),
      recentLogs: await AuditLog.find({
        timestamp: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) }
      }),
      systemState: await this.captureSystemState(),
      networkLogs: await this.captureNetworkLogs()
    };

    // Store securely
    await ForensicEvidence.create({
      timestamp: new Date(),
      data: evidence,
      hash: crypto.createHash('sha256').update(JSON.stringify(evidence)).digest('hex')
    });
  }
}
```

## 3. COMPLIANCE & REGULATIONS

### GDPR Compliance

```typescript
class GDPRCompliance {
  // Right to Access
  static async exportUserData(userId: string): Promise<any> {
    return {
      personalData: await User.findById(userId),
      vaultItems: await VaultItem.find({ userId }),
      activityLogs: await ActivityLog.find({ userId }),
      sessions: await Session.find({ userId })
    };
  }

  // Right to Erasure
  static async deleteUserData(userId: string): Promise<void> {
    // 1. Export data for backup (required by law)
    const backup = await this.exportUserData(userId);
    await DataRetention.create({ userId, data: backup });

    // 2. Delete all user data
    await User.delete(userId);
    await VaultItem.deleteMany({ userId });
    await Session.deleteMany({ userId });
    
    // 3. Anonymize logs (keep for audit, but remove PII)
    await ActivityLog.updateMany(
      { userId },
      { userId: 'DELETED_USER', email: 'deleted@example.com' }
    );

    // 4. Log deletion
    await AuditLog.create({
      event: 'USER_DATA_DELETED',
      userId,
      timestamp: new Date(),
      reason: 'GDPR_RIGHT_TO_ERASURE'
    });
  }

  // Data Breach Notification (72 hours)
  static async notifyDataBreach(breach: DataBreach): Promise<void> {
    // Notify supervisory authority
    await this.notifySupervisoryAuthority(breach);
    
    // Notify affected users
    if (breach.severity === 'HIGH') {
      await this.notifyAffectedUsers(breach);
    }
    
    // Document notification
    await BreachNotification.create({
      breach,
      notifiedAt: new Date(),
      notificationMethod: 'email'
    });
  }
}
```

### Security Checklists

#### Daily Checks
- [ ] Review security alerts
- [ ] Check failed login attempts
- [ ] Monitor resource usage
- [ ] Verify backup completion
- [ ] Check SSL certificate expiry

#### Weekly Checks
- [ ] Review audit logs
- [ ] Update dependencies
- [ ] Test disaster recovery
- [ ] Review user access
- [ ] Scan for vulnerabilities

#### Monthly Checks
- [ ] Security patches applied
- [ ] Penetration testing
- [ ] Access control review
- [ ] Incident response drill
- [ ] Compliance audit

---

## 🎯 Security Principles

1. **Defense in Depth**: Multiple layers of security
2. **Principle of Least Privilege**: Minimal necessary access
3. **Fail Secure**: System fails to secure state
4. **Zero Trust**: Never trust, always verify
5. **Security by Design**: Built-in, not bolted-on

## 📚 Additional Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CIS Controls](https://www.cisecurity.org/controls/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [GDPR Guidelines](https://gdpr.eu/)
