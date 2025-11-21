export interface AppConfig {
  port: number;
  env: string;
  apiVersion: string;
  mongodb: {
    uri: string;
    testUri: string;
  };
  redis: {
    url: string;
  };
  jwt: {
    secret: string;
    expiresIn: string;
    refreshSecret: string;
    refreshExpiresIn: string;
  };
  encryption: {
    serverKey: string;
    algorithm: string;
  };
  aws: {
    region: string;
    accessKeyId: string;
    secretAccessKey: string;
    kmsKeyId: string;
  };
  email: {
    service: string;
    host: string;
    port: number;
    secure: boolean;
    user: string;
    password: string;
    from: string;
  };
  twilio: {
    accountSid: string;
    authToken: string;
    phoneNumber: string;
  };
  security: {
    bcryptRounds: number;
    argon2MemoryCost: number;
    argon2TimeCost: number;
    argon2Parallelism: number;
  };
  otp: {
    expiryMinutes: number;
    maxAttempts: number;
    length: number;
  };
  rateLimit: {
    windowMs: number;
    maxRequests: number;
    authMaxRequests: number;
    otpMaxRequests: number;
  };
  session: {
    timeoutMinutes: number;
    maxSessionsPerUser: number;
  };
  features: {
    enable2FA: boolean;
    enableDeviceTrust: boolean;
    enableEmailOTP: boolean;
    enableSMSOTP: boolean;
  };
}

const config: AppConfig = {
  port: parseInt(process.env.PORT || '5000', 10),
  env: process.env.NODE_ENV || 'development',
  apiVersion: process.env.API_VERSION || 'v1',
  
  mongodb: {
    uri: process.env.MONGODB_URI || 'mongodb://localhost:27017/password_manager_db',
    testUri: process.env.MONGODB_TEST_URI || 'mongodb://localhost:27017/password_manager_test'
  },
  
  redis: {
    url: process.env.REDIS_URL || 'redis://localhost:6379'
  },
  
  jwt: {
    secret: process.env.JWT_SECRET || 'change-this-secret',
    expiresIn: process.env.JWT_EXPIRES_IN || '15m',
    refreshSecret: process.env.JWT_REFRESH_SECRET || 'change-this-refresh-secret',
    refreshExpiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '7d'
  },
  
  encryption: {
    serverKey: process.env.SERVER_ENCRYPTION_KEY || '',
    algorithm: 'aes-256-gcm'
  },
  
  aws: {
    region: process.env.AWS_REGION || 'us-east-1',
    accessKeyId: process.env.AWS_ACCESS_KEY_ID || '',
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY || '',
    kmsKeyId: process.env.KMS_KEY_ID || ''
  },
  
  email: {
    service: process.env.EMAIL_SERVICE || 'gmail',
    host: process.env.EMAIL_HOST || 'smtp.gmail.com',
    port: parseInt(process.env.EMAIL_PORT || '587', 10),
    secure: process.env.EMAIL_SECURE === 'true',
    user: process.env.EMAIL_USER || '',
    password: process.env.EMAIL_PASSWORD || '',
    from: process.env.EMAIL_FROM || 'Password Manager <noreply@passwordmanager.com>'
  },
  
  twilio: {
    accountSid: process.env.TWILIO_ACCOUNT_SID || '',
    authToken: process.env.TWILIO_AUTH_TOKEN || '',
    phoneNumber: process.env.TWILIO_PHONE_NUMBER || ''
  },
  
  security: {
    bcryptRounds: parseInt(process.env.BCRYPT_ROUNDS || '12', 10),
    argon2MemoryCost: parseInt(process.env.ARGON2_MEMORY_COST || '65536', 10),
    argon2TimeCost: parseInt(process.env.ARGON2_TIME_COST || '3', 10),
    argon2Parallelism: parseInt(process.env.ARGON2_PARALLELISM || '4', 10)
  },
  
  otp: {
    expiryMinutes: parseInt(process.env.OTP_EXPIRY_MINUTES || '5', 10),
    maxAttempts: parseInt(process.env.OTP_MAX_ATTEMPTS || '3', 10),
    length: parseInt(process.env.OTP_LENGTH || '6', 10)
  },
  
  rateLimit: {
    windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '900000', 10),
    maxRequests: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS || '100', 10),
    authMaxRequests: parseInt(process.env.AUTH_RATE_LIMIT_MAX || '5', 10),
    otpMaxRequests: parseInt(process.env.OTP_RATE_LIMIT_MAX || '3', 10)
  },
  
  session: {
    timeoutMinutes: parseInt(process.env.SESSION_TIMEOUT_MINUTES || '30', 10),
    maxSessionsPerUser: parseInt(process.env.MAX_SESSIONS_PER_USER || '5', 10)
  },
  
  features: {
    enable2FA: process.env.ENABLE_2FA === 'true',
    enableDeviceTrust: process.env.ENABLE_DEVICE_TRUST === 'true',
    enableEmailOTP: process.env.ENABLE_EMAIL_OTP === 'true',
    enableSMSOTP: process.env.ENABLE_SMS_OTP === 'true'
  }
};

// Validate critical configuration
const validateConfig = () => {
  const required = [
    'JWT_SECRET',
    'MONGODB_URI'
  ];

  const missing = required.filter(key => !process.env[key]);

  if (missing.length > 0 && process.env.NODE_ENV === 'production') {
    throw new Error(`Missing required environment variables: ${missing.join(', ')}`);
  }
};

validateConfig();

export default config;
