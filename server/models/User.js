const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  passwordHash: { type: String, required: true },
  encryptionSalt: { type: String, required: true }, // will use Day 3
}, { timestamps: true });

module.exports = mongoose.model('User', userSchema);
