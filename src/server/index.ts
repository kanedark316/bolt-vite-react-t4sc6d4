import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import connectDB from '../config/db';
import authRoutes from './routes/auth';
import userRoutes from './routes/users';

dotenv.config();

const app = express();

// Connect to MongoDB
connectDB();

// Middleware
app.use(cors());
app.use(express.json());

// Routes
app.use('/api/auth', authRoutes);
app.use('/api/users', userRoutes);

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});