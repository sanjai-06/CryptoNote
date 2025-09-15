const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const auth = require('../middleware/auth');
const Password = require('../models/Password');
const User = require('../models/User');
const { sendPasswordChangeNotification } = require('../services/emailService');

const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY; // must be 32 chars for aes-256
const IV_LENGTH = 16; // AES block size

function encrypt(text) {
  let iv = crypto.randomBytes(IV_LENGTH);
  let cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
  let encrypted = cipher.update(text);
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  return iv.toString('hex') + ':' + encrypted.toString('hex');
}

function decrypt(text) {
  try {
    console.log("Decrypting text:", text);

    if (!text.includes(":")) {
      // Already plain text, return as is
      console.log("Text doesn't contain ':', returning as plain text");
      return text;
    }

    const [ivHex, encryptedText] = text.split(":");
    console.log("IV hex:", ivHex);
    console.log("Encrypted text:", encryptedText);

    const iv = Buffer.from(ivHex, "hex");
    const encryptedTextBuffer = Buffer.from(encryptedText, "hex");

    const decipher = crypto.createDecipheriv(
      "aes-256-cbc",
      Buffer.from(ENCRYPTION_KEY),
      iv
    );

    let decrypted = decipher.update(encryptedTextBuffer);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    const result = decrypted.toString();
    console.log("Decrypted result:", result);
    return result;
  } catch (error) {
    console.error("Decryption error:", error);
    console.error("Failed to decrypt text:", text);
    return text; // Return original text if decryption fails
  }
}


// POST /api/passwords
router.post('/', auth, async (req, res) => {
  try {
    console.log("REQ.USER:", req.user);
    console.log("BODY:", req.body);

    const { website, username, password, category } = req.body;

    const encryptedPassword = encrypt(password);

    const newPassword = new Password({
      userId: req.user.id,
      website,
      username,
      password: encryptedPassword,
      category: category || 'Personal'
    });

    const savedPassword = await newPassword.save();

    // Send email notification
    try {
      const user = await User.findById(req.user.id);
      if (user) {
        await sendPasswordChangeNotification(user.email, user.username, 'created');
      }
    } catch (emailError) {
      console.error('Failed to send email notification:', emailError);
      // Don't fail the password creation if email fails
    }

    res.json(savedPassword);
  } catch (err) {
    console.error("Error in /api/passwords:", err);
    res.status(500).json({ message: "Server Error", error: err.message });
  }
});

// GET /api/passwords
// GET /api/passwords
router.get('/', auth, async (req, res) => {
  try {
    console.log("REQ.USER:", req.user);

    const passwords = await Password.find({ userId: req.user.id });
    console.log("Found passwords:", passwords);

    const decryptedPasswords = passwords.map(p => ({
      ...p._doc,
      password: decrypt(p.password)
    }));

    res.json(decryptedPasswords);
  } catch (err) {
    console.error("Error in GET /api/passwords:", err);
    res.status(500).json({ message: "Server Error", error: err.message });
  }
});
// PUT /api/passwords/:id
router.put('/:id', auth, async (req, res) => {
  try {
    const { website, username, password, category } = req.body;
    const encryptedPassword = encrypt(password);
    const updated = await Password.findOneAndUpdate(
      { _id: req.params.id, userId: req.user.id },
      { website, username, password: encryptedPassword, category: category || 'Personal' },
      { new: true }
    );

    // Send email notification
    try {
      const user = await User.findById(req.user.id);
      if (user) {
        await sendPasswordChangeNotification(user.email, user.username, 'updated');
      }
    } catch (emailError) {
      console.error('Failed to send email notification:', emailError);
      // Don't fail the password update if email fails
    }

    res.json({
      ...updated._doc,
      password: decrypt(updated.password)
    });
  } catch (err) {
    res.status(500).json({ message: "Server Error", error: err.message });
  }
});

// DELETE /api/passwords/:id
router.delete('/:id', auth, async (req, res) => {
  try {
    await Password.findOneAndDelete({ _id: req.params.id, userId: req.user.id });
    res.json({ message: "Deleted successfully" });
  } catch (err) {
    res.status(500).json({ message: "Server Error", error: err.message });
  }
});



module.exports = router;
