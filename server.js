const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(cors());

// 1. Connect to MongoDB Atlas
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('MongoDB connected successfully'))
  .catch((err) => console.error('MongoDB connection error:', err));

// 2. Define User Schema
const UserSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, default: 'user' },
  phone:{type: String, default:''}
});

const User = mongoose.model('User', UserSchema);

// 3. Register Route (Signup)
app.post('/api/signup', async (req, res) => {
  try {
    const { email, password,role,phone } = req.body;
    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ message: 'User already exists' });

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = await User.create({ email, password: hashedPassword,role: role||'user',phone:phone});

    res.status(201).json({ message: 'User registered successfully!' });
  } catch (error) {
    console.error("signup error detailes:",error);
    res.status(500).json({ error: error.message });
  }
});

// 4. Login Route (Signin)
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: 'User not found' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: 'Invalid credentials' });

    const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1d' });
    res.json({
       token,
       role: user.role,
       email: user.email,
       phone: user.phone || 'N/A',
       message: 'Login successful'
       });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});


app.get('/api/users', async (req, res) => {
  try {
    const users = await User.find({}, '-password');
    res.json(users);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});


app.listen(process.env.PORT, () => console.log(`Server running on port ${process.env.PORT}`));