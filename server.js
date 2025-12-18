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

// MongoDB Connection with improved options and logging
console.log('⏳ Attempting to connect to MongoDB...');
if (MONGODB_URI) {
    mongoose.connect(MONGODB_URI)
        .then(() => console.log('✅ Connected to MongoDB Atlas successfully!'))
        .catch(err => {
            console.error('❌ MongoDB connection error details:');
            console.error(err);
        });
} else {
    console.error('❌ MONGODB_URI is undefined! Check your environment variables.');
}

// Debug connection state
mongoose.connection.on('error', err => {
    console.error('⚠️ Mongoose connection error:', err);
});
mongoose.connection.on('disconnected', () => {
    console.warn('⚠️ Mongoose disconnected');
});

// ==================== MODELS ====================

const UserSchema = new mongoose.Schema({
    name: { type: String, required: true },
    phone: { type: String, required: true, unique: true },
    email: { type: String, default: "" },
    password: { type: String, required: true },
    role: { type: String, default: 'user' },
    createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', UserSchema);

// Tự động dọn dẹp các Index cũ của Email để tránh lỗi khi bỏ trống Email
User.collection.dropIndex('email_1').catch(() => {
    // Không sao nếu index này không tồn tại
});

const ApartmentSchema = new mongoose.Schema({
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
        if (mongoose.connection.readyState !== 1) {
            return res.status(503).json({
                success: false,
                message: 'Server đang kết nối cơ sở dữ liệu, vui lòng đợi vài giây rồi thử lại.'
            });
        }

        const { name, email, phone, password, adminCode } = req.body;

        if (!name || !phone || !password) {
            return res.status(400).json({ success: false, message: 'Vui lòng điền đầy đủ thông tin (Tên, SĐT, Mật khẩu)' });
        }

        // Kiểm tra số điện thoại đã tồn tại chưa
        const existingUser = await User.findOne({ phone });
        if (existingUser) {
            return res.status(400).json({ success: false, message: 'Số điện thoại này đã được đăng ký tài khoản' });
        }

        let role = 'user';
        if (adminCode === 'ADMIN2025') {
            role = 'admin';
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const newUser = new User({
            name,
            email: email || '',
            phone,
            password: hashedPassword,
            role
        });

        await newUser.save();

        const token = jwt.sign(
            { id: newUser._id, phone: newUser.phone, name: newUser.name, role: newUser.role },
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
                phone: newUser.phone,
                role: newUser.role
            }
        });

    } catch (error) {
        console.error('Register error:', error);
        res.status(500).json({ success: false, message: 'Lỗi hệ thống khi đăng ký' });
    }
});

// Login user
app.post('/api/login', async (req, res) => {
    try {
        if (mongoose.connection.readyState !== 1) {
            return res.status(503).json({ success: false, message: 'Server đang bận, vui lòng thử lại' });
        }

        const { phone, password } = req.body;

        if (!phone || !password) {
            return res.status(400).json({ success: false, message: 'Vui lòng nhập SĐT và mật khẩu' });
        }

        const user = await User.findOne({ phone });
        if (!user) {
            return res.status(401).json({ success: false, message: 'Số điện thoại hoặc mật khẩu không đúng' });
        }

        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).json({ success: false, message: 'Số điện thoại hoặc mật khẩu không đúng' });
        }

        const token = jwt.sign(
            { id: user._id, phone: user.phone, name: user.name, role: user.role || 'user' },
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
                phone: user.phone,
                role: user.role || 'user'
            }
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ success: false, message: 'Lỗi server, vui lòng thử lại' });
    }
});

// Get user info
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

app.post('/api/apartments', authenticateToken, async (req, res) => {
    try {
        const { data } = req.body;
        if (!data) return res.status(400).json({ success: false, message: 'Dữ liệu không hợp lệ' });

        await ApartmentData.findOneAndUpdate(
            {},
            { data, updatedAt: new Date() },
            { upsert: true, new: true }
        );

        res.json({ success: true, message: 'Đã lưu dữ liệu thành công' });
    } catch (error) {
        console.error('Save data error:', error);
        res.status(500).json({ success: false, message: 'Lỗi server khi lưu dữ liệu' });
    }
});

// ==================== USER MANAGEMENT ROUTES ====================

// Delete user account (Admin only)
app.delete('/api/users/:phone', authenticateToken, async (req, res) => {
    try {
        // Chỉ Admin mới có quyền xóa tài khoản
        if (req.user.role !== 'admin') {
            return res.status(403).json({ success: false, message: 'Bạn không có quyền thực hiện hành động này' });
        }

        const { phone } = req.params;
        const result = await User.findOneAndDelete({ phone });

        if (result) {
            res.json({ success: true, message: 'Đã xóa tài khoản người dùng vĩnh viễn' });
        } else {
            res.status(404).json({ success: false, message: 'Không tìm thấy tài khoản để xóa' });
        }
    } catch (error) {
        console.error('Delete user error:', error);
        res.status(500).json({ success: false, message: 'Lỗi server khi xóa tài khoản' });
    }
});

// ==================== START SERVER ====================

app.listen(PORT, () => {
    console.log(`🚀 Server is running on http://localhost:${PORT}`);
});
