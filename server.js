// Backend Authentication System (Node.js + Express.js)
// - Handles user sign-up, login, email verification via Brevo
// - Stores profile images via Cloudinary
// - Uses Deta Space for hosting

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const multer = require('multer');
const { Deta } = require('deta'); // Database
const cloudinary = require('cloudinary').v2;

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(cors());

// Database Setup (Deta Base)
const deta = Deta(process.env.DETA_PROJECT_KEY);
const usersDB = deta.Base('users');

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

// Signup Endpoint
app.post('/signup', async (req, res) => {
  const { email, password } = req.body;
  const existingUser = await usersDB.get(email);
  if (existingUser) return res.status(400).json({ message: 'Email already exists' });

  const hashedPassword = await bcrypt.hash(password, 10);
  const token = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: '1h' });
  
  await usersDB.put({ email, password: hashedPassword, verified: false });
  
  const verificationLink = `https://your-backend-url/verify?token=${token}`;
  await transporter.sendMail({
    from: process.env.BREVO_EMAIL,
    to: email,
    subject: 'Verify Your Email',
    text: `Click the link to verify your account: ${verificationLink}`,
  });
  
  res.json({ message: 'Signup successful. Check your email to verify.' });
});

// Email Verification Endpoint
app.get('/verify', async (req, res) => {
  try {
    const { token } = req.query;
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    await usersDB.update({ verified: true }, decoded.email);
    res.json({ message: 'Email verified successfully!' });
  } catch (error) {
    res.status(400).json({ message: 'Invalid or expired token' });
  }
});

// Login Endpoint
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await usersDB.get(email);
  if (!user || !user.verified) return res.status(400).json({ message: 'User not found or not verified' });
  
  const passwordMatch = await bcrypt.compare(password, user.password);
  if (!passwordMatch) return res.status(401).json({ message: 'Invalid password' });
  
  const token = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: '7d' });
  res.json({ message: 'Login successful', token });
});

// Profile Picture Upload Endpoint
const upload = multer({ storage: multer.memoryStorage() });
app.post('/upload', upload.single('image'), async (req, res) => {
  try {
    const file = req.file;
    if (!file) return res.status(400).json({ message: 'No file uploaded' });
    
    const result = await cloudinary.uploader.upload_stream({ resource_type: 'image' }, (error, result) => {
      if (error) return res.status(500).json({ message: 'Upload failed' });
      res.json({ imageUrl: result.secure_url });
    }).end(file.buffer);
  } catch (error) {
    res.status(500).json({ message: 'Upload error' });
  }
});

// Start Server
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
