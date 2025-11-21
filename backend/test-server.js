// Minimal test server for vault testing
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');

const app = express();

// Middleware
app.use(cors());
app.use(express.json({ limit: '10mb' }));

// MongoDB connection
mongoose.connect('mongodb+srv://khoilam3789_db_user:d6jBtNrJUb4IHcMs@data.jqzpt6k.mongodb.net/password_manager?retryWrites=true&w=majority&appName=data')
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB error:', err));

// Vault Item Schema
const vaultItemSchema = new mongoose.Schema({
  userId: { type: String, required: true },
  type: { type: String, enum: ['password', 'note', 'card', 'identity'], default: 'password' },
  name: { type: String, required: true },
  encryptedData: { type: String, required: true },
  iv: { type: String, required: true },
  category: String,
  favorite: { type: Boolean, default: false },
  tags: [String],
  notes: { type: String, maxlength: 1000 },
  lastAccessed: Date
}, { timestamps: true });

const VaultItem = mongoose.model('VaultItem', vaultItemSchema);

// Routes
app.post('/api/v1/vault', async (req, res) => {
  try {
    console.log('Received vault creation request:', req.body);
    
    const { type, name, encryptedData, iv, category, favorite, tags, notes } = req.body;
    
    if (!name || !encryptedData || !iv) {
      return res.status(400).json({
        success: false,
        message: 'Name, encrypted data, and IV are required',
      });
    }

    const item = await VaultItem.create({
      userId: 'test-user-123', // Hardcoded for testing
      type: type || 'password',
      name,
      encryptedData,
      iv,
      category,
      favorite: favorite || false,
      tags: tags || [],
      notes,
    });

    console.log('Vault item created:', item._id);

    res.status(201).json({
      success: true,
      data: item,
    });
  } catch (error) {
    console.error('Create vault item error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to create vault item',
      error: error.message
    });
  }
});

app.get('/api/v1/vault', async (req, res) => {
  try {
    const items = await VaultItem.find({ userId: 'test-user-123' })
      .sort({ favorite: -1, updatedAt: -1 });

    res.status(200).json({
      success: true,
      data: items,
    });
  } catch (error) {
    console.error('Get vault items error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to retrieve vault items',
    });
  }
});

app.get('/api/v1/vault/:id', async (req, res) => {
  try {
    const item = await VaultItem.findOne({ 
      _id: req.params.id, 
      userId: 'test-user-123' 
    });

    if (!item) {
      return res.status(404).json({
        success: false,
        message: 'Vault item not found',
      });
    }

    // Update last accessed
    item.lastAccessed = new Date();
    await item.save();

    res.status(200).json({
      success: true,
      data: item,
    });
  } catch (error) {
    console.error('Get vault item error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to retrieve vault item',
    });
  }
});

// Also add auth routes that frontend needs
// For testing: Use a fixed salt and pre-encrypted DEK that matches test credentials
// Test credentials: email='test@test.com', password='Test123!'
const FIXED_SALT = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='; // Base64 of 32 zero bytes
const FIXED_DEK = 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB8='; // Pre-generated encrypted DEK
const FIXED_IV = 'CCCCCCCCCCCCCCCCCCCCCA=='; // Pre-generated IV

app.post('/api/v1/auth/login', (req, res) => {
  console.log('Login attempt for:', req.body.email);
  
  // For test server, accept any password and return fixed encrypted values
  // In real app, this would validate authKeyHash against DB
  res.json({
    success: true,
    token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiJ0ZXN0LXVzZXItMTIzIiwiZW1haWwiOiJ0ZXN0QHRlc3QuY29tIn0.test',
    refreshToken: 'test-refresh-token',
    user: { 
      _id: 'test-user-123',
      email: req.body.email || 'test@test.com',
      isEmailVerified: true
    },
    encryptedDEK: FIXED_DEK,
    dekIV: FIXED_IV
  });
});

app.post('/api/v1/auth/get-salt', (req, res) => {
  // Return fixed salt for testing so encryption keys are consistent
  console.log('Salt request for:', req.body.email);
  
  res.json({
    success: true,
    data: {
      salt: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=' // Fixed salt for testing
    }
  });
});

app.listen(5000, () => {
  console.log('Test server running on port 5000');
});
