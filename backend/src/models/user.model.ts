import mongoose, { Document, Schema } from 'mongoose';

export interface IUser extends Document {
  email: string;
  username: string;
  passwordHash: string;
  salt: string;
  masterKeyHash: string;
  protectedSymmetricKey: string;
  dekIV: string;
  publicKey: string;
  privateKeyEncrypted: string;
  twoFactorEnabled: boolean;
  twoFactorSecret?: string;
  backupCodes?: string[];
  createdAt: Date;
  updatedAt: Date;
  lastLoginAt?: Date;
  isEmailVerified: boolean;
  emailVerificationToken?: string;
  emailVerificationExpires?: Date;
  passwordResetToken?: string;
  passwordResetExpires?: Date;
  failedLoginAttempts: number;
  accountLockedUntil?: Date;
}

const userSchema = new Schema<IUser>(
  {
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
    },
    username: {
      type: String,
      required: true,
      unique: true,
      trim: true,
      minlength: 3,
      maxlength: 30,
    },
    passwordHash: {
      type: String,
      required: true,
    },
    salt: {
      type: String,
      required: true,
    },
    masterKeyHash: {
      type: String,
      required: false,
      default: '',
    },
    protectedSymmetricKey: {
      type: String,
      required: true,
    },
    dekIV: {
      type: String,
      required: true,
    },
    publicKey: {
      type: String,
      required: false,
      default: '',
    },
    privateKeyEncrypted: {
      type: String,
      required: false,
      default: '',
    },
    twoFactorEnabled: {
      type: Boolean,
      default: false,
    },
    twoFactorSecret: {
      type: String,
      select: false,
    },
    backupCodes: {
      type: [String],
      select: false,
    },
    lastLoginAt: {
      type: Date,
    },
    isEmailVerified: {
      type: Boolean,
      default: false,
    },
    emailVerificationToken: {
      type: String,
      select: false,
    },
    emailVerificationExpires: {
      type: Date,
      select: false,
    },
    passwordResetToken: {
      type: String,
      select: false,
    },
    passwordResetExpires: {
      type: Date,
      select: false,
    },
    failedLoginAttempts: {
      type: Number,
      default: 0,
    },
    accountLockedUntil: {
      type: Date,
    },
  },
  {
    timestamps: true,
  }
);

// Indexes for performance
// Note: email and username already have indexes from unique: true
userSchema.index({ createdAt: -1 });
userSchema.index({ emailVerificationToken: 1 });

export const User = mongoose.model<IUser>('User', userSchema);
