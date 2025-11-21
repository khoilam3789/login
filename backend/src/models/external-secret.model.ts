import mongoose, { Document, Schema } from 'mongoose';

export interface IExternalSecret extends Document {
  userId: mongoose.Types.ObjectId;
  name: string;
  issuer: string;
  encryptedSecret: string;
  accountName?: string;
  icon?: string;
  category?: string;
  notes?: string;
  createdAt: Date;
  updatedAt: Date;
  lastUsed?: Date;
}

const externalSecretSchema = new Schema<IExternalSecret>(
  {
    userId: {
      type: Schema.Types.ObjectId,
      ref: 'User',
      required: true,
      index: true,
    },
    name: {
      type: String,
      required: true,
      trim: true,
    },
    issuer: {
      type: String,
      required: true,
      trim: true,
    },
    encryptedSecret: {
      type: String,
      required: true,
    },
    accountName: {
      type: String,
      trim: true,
    },
    icon: {
      type: String,
      trim: true,
    },
    category: {
      type: String,
      enum: ['social', 'financial', 'email', 'cloud', 'gaming', 'work', 'other'],
      default: 'other',
    },
    notes: {
      type: String,
      trim: true,
      maxlength: 500,
    },
    lastUsed: {
      type: Date,
    },
  },
  {
    timestamps: true,
  }
);

// Indexes
externalSecretSchema.index({ userId: 1, name: 1 });
externalSecretSchema.index({ userId: 1, category: 1 });
externalSecretSchema.index({ userId: 1, createdAt: -1 });

export const ExternalSecret = mongoose.model<IExternalSecret>(
  'ExternalSecret',
  externalSecretSchema
);
