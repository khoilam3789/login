import mongoose, { Document, Schema } from 'mongoose';

export interface IVaultItem extends Document {
  userId: mongoose.Types.ObjectId;
  type: 'password' | 'note' | 'card' | 'identity';
  name: string;
  encryptedData: string;
  iv: string;
  category?: string;
  favorite: boolean;
  tags?: string[];
  notes?: string;
  createdAt: Date;
  updatedAt: Date;
  lastAccessed?: Date;
}

const vaultItemSchema = new Schema<IVaultItem>(
  {
    userId: {
      type: Schema.Types.ObjectId,
      ref: 'User',
      required: true,
      index: true,
    },
    type: {
      type: String,
      enum: ['password', 'note', 'card', 'identity'],
      required: true,
      default: 'password',
    },
    name: {
      type: String,
      required: true,
      trim: true,
    },
    encryptedData: {
      type: String,
      required: true,
    },
    iv: {
      type: String,
      required: true,
    },
    category: {
      type: String,
      trim: true,
    },
    favorite: {
      type: Boolean,
      default: false,
    },
    tags: {
      type: [String],
      default: [],
    },
    notes: {
      type: String,
      trim: true,
      maxlength: 1000,
    },
    lastAccessed: {
      type: Date,
    },
  },
  {
    timestamps: true,
  }
);

// Indexes
vaultItemSchema.index({ userId: 1, type: 1 });
vaultItemSchema.index({ userId: 1, favorite: 1 });
vaultItemSchema.index({ userId: 1, category: 1 });
vaultItemSchema.index({ userId: 1, createdAt: -1 });
vaultItemSchema.index({ userId: 1, tags: 1 });

export const VaultItem = mongoose.model<IVaultItem>('VaultItem', vaultItemSchema);
