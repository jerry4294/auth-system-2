const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const { encrypt, decrypt } = require('../utils/encryption');

const UserSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    minlength: 3,
    maxlength: 50,
    match: [/^[a-zA-Z0-9_]+$/, 'Username can only contain letters, numbers and underscores']
  },
  email: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    lowercase: true,
    validate: {
      validator: function(v) {
        return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);
      },
      message: props => `${props.value} is not a valid email address!`
    },
    set: encrypt
  },
  password: {
    type: String,
    required: true,
    select: false,
    minlength: 8
  },
  role: {
    type: String,
    default: 'user',
    enum: ['user', 'admin']
  },
  bio: {
    type: String,
    maxlength: 500,
    default: '',
    set: (value) => value ? encrypt(value) : '',
    validate: {
      validator: function(v) {
        return !/<[^>]*>/.test(decrypt(v || ''));
      },
      message: 'Bio cannot contain HTML tags'
    }
  },
  googleId: String,
  isVerified: {
    type: Boolean,
    default: false
  }
}, { 
  timestamps: true,
  toJSON: {
    transform: function(doc, ret) {
      delete ret.password;
      delete ret.__v;
      if (ret.email) ret.email = decrypt(ret.email);
      if (ret.bio) ret.bio = decrypt(ret.bio);
    }
  }
});

UserSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  
  try {
    const salt = await bcrypt.genSalt(12);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (err) {
    next(err);
  }
});

UserSchema.methods.comparePassword = async function(candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

UserSchema.methods.decryptField = function(field) {
  if (this[field]) {
    return decrypt(this[field]);
  }
  return '';
};

module.exports = mongoose.model('User', UserSchema);