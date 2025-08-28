const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const auth = require('../middleware/auth');
const { validatePasswordStrength, isStrongMasterPassword } = require('../utils/passwordValidator');
const { sendMasterPasswordChangeNotification } = require('../services/emailService');

const router = express.Router();

// REGISTER
router.post('/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;

    // Validate password strength for master password
    const passwordValidation = validatePasswordStrength(password);
    if (!passwordValidation.isValidMasterPassword) {
      return res.status(400).json({
        message: "Master password is not strong enough",
        errors: passwordValidation.errors,
        warnings: passwordValidation.warnings,
        suggestions: passwordValidation.suggestions,
        strength: passwordValidation.strength,
        score: passwordValidation.score
      });
    }

    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ message: "Email already in use" });

    // Hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Save user
    const newUser = new User({ username, email, password: hashedPassword });
    await newUser.save();

    res.status(201).json({
      message: "User registered successfully with strong master password",
      passwordStrength: passwordValidation.strength
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// LOGIN
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Check user
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: "Invalid credentials" });

    // Check password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: "Invalid credentials" });

    // Create token
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "1h" });

    res.json({ token });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// CHANGE MASTER PASSWORD
router.put('/change-password', auth, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;

    // Get user
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ message: "User not found" });

    // Verify current password
    const isCurrentPasswordValid = await bcrypt.compare(currentPassword, user.password);
    if (!isCurrentPasswordValid) {
      return res.status(400).json({ message: "Current password is incorrect" });
    }

    // Validate new password strength
    const passwordValidation = validatePasswordStrength(newPassword);
    if (!passwordValidation.isValidMasterPassword) {
      return res.status(400).json({
        message: "New master password is not strong enough",
        errors: passwordValidation.errors,
        warnings: passwordValidation.warnings,
        suggestions: passwordValidation.suggestions,
        strength: passwordValidation.strength,
        score: passwordValidation.score
      });
    }

    // Check if new password is different from current
    const isSamePassword = await bcrypt.compare(newPassword, user.password);
    if (isSamePassword) {
      return res.status(400).json({ message: "New password must be different from current password" });
    }

    // Hash new password
    const salt = await bcrypt.genSalt(10);
    const hashedNewPassword = await bcrypt.hash(newPassword, salt);

    // Update password
    user.password = hashedNewPassword;
    await user.save();

    // Send email notification
    try {
      await sendMasterPasswordChangeNotification(user.email, user.username);
    } catch (emailError) {
      console.error('Failed to send email notification:', emailError);
      // Don't fail the password change if email fails
    }

    res.json({
      message: "Master password changed successfully",
      passwordStrength: passwordValidation.strength
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// VALIDATE PASSWORD STRENGTH (for frontend validation)
router.post('/validate-password', (req, res) => {
  try {
    const { password } = req.body;
    const validation = validatePasswordStrength(password);
    res.json(validation);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

module.exports = router;
