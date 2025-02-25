// Backend Authentication System (Node.js + Express.js)
// - Handles user sign-up, login, email verification via Brevo
// - Stores profile images via Cloudinary

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const multer = require('multer');
const cloudinary = require('cloudinary').v2;

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json()); 
app.use(express.urlencoded({ extended: true }));
app.use(cors());

// Cloudinary Setup (For Profile Pictures)
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// Email Transporter (Brevo/Sendinblue SMTP)
const transporter = nodemailer.createTransport({
  host: 'smtp-relay.brevo.com',
  port: 587,
  auth: {
    user: process.env.BREVO_EMAIL,
    pass: process.env.BREVO_API_KEY,
  },
});

// Mock Database (Replace with real DB later)
const usersDB = new Map();

// Root Endpoint
app.get('/', (req, res) => {
  res.send('Lifelike Backend is Running');
});

// Signup Endpoint
app.post('/signup', async (req, res) => {
  try {
    const { email, password } = req.body;
    console.log(`Signup request received for: ${email}`);

    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password are required' });
    }

    if (usersDB.has(email)) {
      console.log(`User already exists: ${email}`);
      return res.status(400).json({ message: 'Email already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const token = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: '1h' });

    usersDB.set(email, { email, password: hashedPassword, verified: false });

    console.log(`User stored in database: ${JSON.stringify(usersDB.get(email))}`);

    const verificationLink = `https://lifelike-backend.onrender.com/verify?token=${token}`;
    await transporter.sendMail({
      from: process.env.BREVO_EMAIL,
      to: email,
      subject: 'Verify Your Email',
      text: `Click the link to verify your account: ${verificationLink}`,
    });

    console.log(`Verification email sent to: ${email}`);

    res.json({ message: 'Signup successful. Check your email to verify.' });
  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ message: 'Signup failed' });
  }
});

// Start Server
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
