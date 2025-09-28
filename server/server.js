require('dotenv').config();

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const mongoose = require('mongoose');

const authRoutes = require('./routes/auth');
const passwordRoutes = require('./routes/passwords');
const categoryRoutes = require('./routes/categories');

const app = express();

// Security & parsing middleware
app.use(helmet());

// CORS configuration via env
// CORS_ORIGINS can be a comma-separated list
const corsOrigins = (process.env.CORS_ORIGINS || 'http://localhost:5173,http://localhost:5174')
  .split(',')
  .map(o => o.trim());
app.use(cors({
  origin: function (origin, callback) {
    // allow REST clients without origin (e.g., curl/Postman) and same-origin
    if (!origin || corsOrigins.includes(origin)) return callback(null, true);
    return callback(new Error('Not allowed by CORS'));
  },
  credentials: (process.env.CORS_CREDENTIALS || 'false').toLowerCase() === 'true'
}));

app.use(express.json({ limit: '200kb' }));

// Validate encryption key presence and length (32 bytes for AES-256)
const encKey = process.env.ENCRYPTION_KEY || '';
if (!encKey) {
  console.warn('ENCRYPTION_KEY is not set. Password encryption will fail.');
} else if (Buffer.from(encKey).length !== 32) {
  console.warn('ENCRYPTION_KEY must be exactly 32 bytes for AES-256. Current length:', Buffer.from(encKey).length);
}

// Rate limiting (generic)
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP
  standardHeaders: true,
  legacyHeaders: false,
});
app.use('/api/', apiLimiter);

// Routes
app.use('/api/auth', authRoutes);
app.use('/api/passwords', passwordRoutes);
app.use('/api/categories', categoryRoutes);

// MongoDB connection
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('MongoDB Connected'))
  .catch(err => console.error('MongoDB connection error:', err));

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
