import express from 'express';
import jwt from 'jsonwebtoken';
import Admin, { AdminRole } from '../../models/Admin';
import auth from '../middleware/auth';
import { checkPermission } from '../middleware/adminPermissions';

const router = express.Router();

// Admin Login
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    const admin = await Admin.findOne({ email });
    if (!admin) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const isMatch = await admin.comparePassword(password);
    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    // Update last login
    admin.lastLogin = new Date();
    await admin.save();

    const token = jwt.sign(
      { 
        adminId: admin._id,
        role: admin.role,
        permissions: admin.permissions
      },
      process.env.JWT_SECRET,
      { expiresIn: '8h' }
    );

    res.json({ token, role: admin.role, permissions: admin.permissions });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Create new admin (requires super admin)
router.post('/create', auth, checkPermission('canManageAdmins'), async (req, res) => {
  try {
    const { username, email, password, role, permissions } = req.body;

    // Only super admin can create other super admins
    if (role === AdminRole.SUPER_ADMIN && req.admin.role !== AdminRole.SUPER_ADMIN) {
      return res.status(403).json({ message: 'Only super admins can create other super admins' });
    }

    const admin = new Admin({
      username,
      email,
      password,
      role,
      permissions,
      createdBy: req.admin.adminId
    });

    await admin.save();

    res.status(201).json({ message: 'Admin created successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Get all admins (requires super admin)
router.get('/', auth, checkPermission('canManageAdmins'), async (req, res) => {
  try {
    const admins = await Admin.find()
      .select('-password')
      .populate('createdBy', 'username');
    res.json(admins);
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Update admin permissions (requires super admin)
router.put('/:id', auth, checkPermission('canManageAdmins'), async (req, res) => {
  try {
    const { role, permissions } = req.body;
    const adminToUpdate = await Admin.findById(req.params.id);

    if (!adminToUpdate) {
      return res.status(404).json({ message: 'Admin not found' });
    }

    // Prevent modifying super admin unless you're a super admin
    if (adminToUpdate.role === AdminRole.SUPER_ADMIN && req.admin.role !== AdminRole.SUPER_ADMIN) {
      return res.status(403).json({ message: 'Cannot modify super admin permissions' });
    }

    adminToUpdate.role = role;
    adminToUpdate.permissions = permissions;
    await adminToUpdate.save();

    res.json({ message: 'Admin updated successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

export default router;