import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';

const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true
  },
  email: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    lowercase: true
  },
  password: {
    type: String,
    required: true
  },
  forename: String,
  surname: String,
  dateOfBirth: Date,
  subscription: {
    plan: {
      type: String,
      enum: ['basic', 'standard', 'premium'],
      default: null
    },
    startDate: Date,
    nextBillingDate: Date,
    status: {
      type: String,
      enum: ['active', 'cancelled', 'expired'],
      default: null
    }
  },
  isEmailConfirmed: {
    type: Boolean,
    default: false
  },
  confirmationCode: String,
  resetPasswordToken: String,
  resetPasswordExpires: Date,
  createdAt: {
    type: Date,
    default: Date.now
  }
});

// Hash password before saving
userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  
  try {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error) {
    next(error);
  }
});

// Method to compare passwords
userSchema.methods.comparePassword = async function(candidatePassword) {
  return bcrypt.compare(candidatePassword, this.password);
};

const User = mongoose.model('User', userSchema);

export default User;