require('dotenv').config();
console.log("Loaded JWT_SECRET:", process.env.JWT_SECRET); // debug

const express = require('express');
const mongoose = require('mongoose');
const authRoutes = require('./routes/auth');
const passwordRoutes = require('./routes/passwords');


const app = express(); // <-- You forgot this line!

// Middleware
app.use(express.json());

// Routes
app.use('/api/auth', authRoutes);
app.use('/api/passwords', passwordRoutes);

// MongoDB connection
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB Connected"))
  .catch(err => console.error(err));

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
