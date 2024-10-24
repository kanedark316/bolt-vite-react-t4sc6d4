import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';

export enum AdminRole {
  SUPER_ADMIN = 'super_admin',
  CONTENT_MANAGER = 'content_manager',
  ANALYTICS_VIEWER = 'analytics_viewer'
}

export interface AdminPermissions {
  canManageAdmins: boolean;
  canAddContent: boolean;
  canEditContent: boolean;
  canDeleteContent: boolean;
  canViewAnalytics: boolean;
  canManageLiveEvents: boolean;
}

const adminSchema = new mongoose.Schema({
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
  role: {
    type: String,
    enum: Object.values(AdminRole),
    required: true
  },
  permissions: {
    canManageAdmins: {
      type: Boolean,
      default: false
    },
    canAddContent: {
      type: Boolean,
      default: true
    },
    canEditContent: {
      type: Boolean,
      default: true
    },
    canDeleteContent: {
      type: Boolean,
      default: false
    },
    canViewAnalytics: {
      type: Boolean,
      default: true
    },
    canManageLiveEvents: {
      type: Boolean,
      default: false
    }
  },
  createdBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Admin'
  },
  lastLogin: Date,
  createdAt: {
    type: Date,
    default: Date.now
  }
});

// Hash password before saving
adminSchema.pre('save', async function(next) {
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
adminSchema.methods.comparePassword = async function(candidatePassword: string) {
  return bcrypt.compare(candidatePassword, this.password);
};

// Create default super admin if none exists
adminSchema.statics.createDefaultSuperAdmin = async function() {
  const superAdminExists = await this.findOne({ role: AdminRole.SUPER_ADMIN });
  
  if (!superAdminExists) {
    await this.create({
      username: 'superadmin',
      email: 'admin@rewindtv.com',
      password: 'Admin123!@#', // Change this in production
      role: AdminRole.SUPER_ADMIN,
      permissions: {
        canManageAdmins: true,
        canAddContent: true,
        canEditContent: true,
        canDeleteContent: true,
        canViewAnalytics: true,
        canManageLiveEvents: true
      }
    });
    console.log('Default super admin created');
  }
};

const Admin = mongoose.model('Admin', adminSchema);

export default Admin;