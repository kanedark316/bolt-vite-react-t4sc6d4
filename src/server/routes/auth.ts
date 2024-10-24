import express from 'express';
import jwt from 'jsonwebtoken';
import User from '../../models/User';
import { generateConfirmationCode } from '../utils/auth';

const router = express.Router();

// Register
router.post('/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    
    // Check if user already exists
    const existingUser = await User.findOne({ $or: [{ email }, { username }] });
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists' });
    }

    const confirmationCode = generateConfirmationCode();
    
    const user = new User({
      username,
      email,
      password,
      confirmationCode
    });

    await user.save();

    // In a real application, send confirmation email here
    
    res.status(201).json({ message: 'Registration successful. Please check your email for confirmation.' });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Login
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    if (!user.isEmailConfirmed) {
      return res.status(400).json({ message: 'Please confirm your email first' });
    }

    const token = jwt.sign(
      { userId: user._id },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({ token });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Email confirmation
router.post('/confirm', async (req, res) => {
  try {
    const { email, code } = req.body;
    
    const user = await User.findOne({ email, confirmationCode: code });
    if (!user) {
      return res.status(400).json({ message: 'Invalid confirmation code' });
    }

    user.isEmailConfirmed = true;
    user.confirmationCode = undefined;
    await user.save();

    const token = jwt.sign(
      { userId: user._id },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({ token });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

export default router;