require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'apartment-management-secret-key-2024';
const MONGODB_URI = process.env.MONGODB_URI;

// Middleware
app.use(cors());
app.use(express.json());

// MongoDB Connection
if (MONGODB_URI) {
    mongoose.connect(MONGODB_URI)
        .then(() => console.log('✅ Connected to MongoDB Atlas'))
        .catch(err => console.error('❌ MongoDB connection error:', err));
} else {
    console.warn('⚠️ MONGODB_URI not found. Server will not be able to save data to database.');
}

// ==================== MODELS ====================

const UserSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    phone: { type: String, required: true },
    password: { type: String, required: true },
    role: { type: String, default: 'user' },
    createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', UserSchema);

const ApartmentSchema = new mongoose.Schema({
    // We can store the entire array of apartment data or individual rooms
    // Since the original was a simple JSON array of all apartments, 
    // we'll store it as a single document with the data array for simplicity, 
    // or better yet, as individual room records if needed.
    // For now, let's keep it close to the original structure to minimize frontend changes.
    data: { type: Array, required: true },
    updatedAt: { type: Date, default: Date.now }
});

const ApartmentData = mongoose.model('ApartmentData', ApartmentSchema);

// Middleware to verify JWT token
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ success: false, message: 'Access token required' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ success: false, message: 'Invalid or expired token' });
        }
        req.user = user;
        next();
    });
}

// ==================== AUTH ROUTES ====================

// Register new user
app.post('/api/register', async (req, res) => {
    try {
        const { name, email, phone, password, adminCode } = req.body;

        if (!name || !email || !phone || !password) {
            return res.status(400).json({ success: false, message: 'Vui lòng điền đầy đủ thông tin' });
        }

        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({ success: false, message: 'Email không hợp lệ' });
        }

        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ success: false, message: 'Email đã được sử dụng' });
        }

        let role = 'user';
        if (adminCode === 'ADMIN2025') {
            role = 'admin';
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const newUser = new User({
            name,
            email,
            phone,
            password: hashedPassword,
            role
        });

        await newUser.save();

        const token = jwt.sign(
            { id: newUser._id, email: newUser.email, name: newUser.name, role: newUser.role },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.status(201).json({
            success: true,
            message: role === 'admin' ? 'Đăng ký Admin thành công' : 'Đăng ký thành công',
            token,
            user: {
                id: newUser._id,
                name: newUser.name,
                email: newUser.email,
                phone: newUser.phone,
                role: newUser.role
            }
        });

    } catch (error) {
        console.error('Register error:', error);
        res.status(500).json({ success: false, message: 'Lỗi server, vui lòng thử lại' });
    }
});

// Login user
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ success: false, message: 'Vui lòng điền đầy đủ thông tin' });
        }

        const user = await User.findOne({ email });

        if (!user) {
            return res.status(401).json({ success: false, message: 'Email hoặc mật khẩu không đúng' });
        }

        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).json({ success: false, message: 'Email hoặc mật khẩu không đúng' });
        }

        const token = jwt.sign(
            { id: user._id, email: user.email, name: user.name, role: user.role || 'user' },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.json({
            success: true,
            message: 'Đăng nhập thành công',
            token,
            user: {
                id: user._id,
                name: user.name,
                email: user.email,
                phone: user.phone,
                role: user.role || 'user'
            }
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ success: false, message: 'Lỗi server, vui lòng thử lại' });
    }
});

// Verify token and get user info
app.get('/api/me', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.id);

        if (!user) {
            return res.status(404).json({ success: false, message: 'Không tìm thấy người dùng' });
        }

        res.json({
            success: true,
            user: {
                id: user._id,
                name: user.name,
                email: user.email,
                phone: user.phone,
                role: user.role || 'user'
            }
        });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Lỗi server' });
    }
});

// ==================== DATA ROUTES ====================

// Get all apartment data
app.get('/api/apartments', authenticateToken, async (req, res) => {
    try {
        const record = await ApartmentData.findOne().sort({ updatedAt: -1 });
        res.json({
            success: true,
            data: record ? record.data : []
        });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Lỗi lấy dữ liệu' });
    }
});

// Save all apartment data
app.post('/api/apartments', authenticateToken, async (req, res) => {
    try {
        const { data } = req.body;

        if (!data) {
            return res.status(400).json({ success: false, message: 'Dữ liệu không hợp lệ' });
        }

        // We update the existing record or create a new one
        // For simplicity, we just keep one state record in this simple app
        await ApartmentData.findOneAndUpdate(
            {},
            { data, updatedAt: new Date() },
            { upsert: true, new: true }
        );

        res.json({
            success: true,
            message: 'Đã lưu dữ liệu thành công'
        });
    } catch (error) {
        console.error('Save data error:', error);
        res.status(500).json({ success: false, message: 'Lỗi server khi lưu dữ liệu' });
    }
});

// ==================== START SERVER ====================

app.listen(PORT, () => {
    console.log(`🚀 Server is running on http://localhost:${PORT}`);
    console.log(`📝 API Endpoints:`);
    console.log(`   POST /api/register - Đăng ký tài khoản`);
    console.log(`   POST /api/login    - Đăng nhập`);
    console.log(`   GET  /api/me       - Lấy thông tin user (cần token)`);
});
