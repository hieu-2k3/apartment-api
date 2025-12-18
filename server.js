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
        .then(() => {
            console.log('✅ Connected to MongoDB Atlas successfully!');
            // Chạy sau khi đã kết nối thành công để tránh lỗi timeout
            if (mongoose.connection.db) {
                mongoose.connection.db.collection('users').dropIndex('email_1')
                    .then(() => console.log('🗑️ Old email index dropped'))
                    .catch(() => { }); // Vô tư nếu không có index
            }
        })
        .catch(err => {
            console.error('❌ MongoDB connection error details:');
            console.error(err);
        });
} else {
    console.error('❌ MONGODB_URI is undefined!');
}

// Health Check cho Render
app.get('/', (req, res) => res.send('API is Live!'));

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

// Email index cleanup moved inside connection success above

const ApartmentSchema = new mongoose.Schema({
    data: { type: Array, required: true },
    updatedAt: { type: Date, default: Date.now }
});

const ApartmentData = mongoose.model('ApartmentData', ApartmentSchema);

const InvoiceSchema = new mongoose.Schema({
    roomId: { type: String, required: true },
    roomName: { type: String, required: true },
    representativeName: { type: String, default: "" },
    residentCount: { type: Number, default: 1 },
    month: { type: Number, required: true },
    year: { type: Number, required: true },
    roomPrice: { type: Number, default: 0 },
    electricity: {
        oldValue: { type: Number, default: 0 },
        newValue: { type: Number, default: 0 },
        price: { type: Number, default: 2500 }
    },
    waterFee: { type: Number, default: 0 }, // per person calculation
    internetFee: { type: Number, default: 0 }, // per person calculation
    serviceFee: { type: Number, default: 0 }, // per person calculation
    parkingFee: { type: Number, default: 0 },
    otherFee: { type: Number, default: 0 },
    totalAmount: { type: Number, required: true },
    status: { type: String, enum: ['pending', 'paid'], default: 'pending' },
    paymentRequest: { type: Boolean, default: false },
    createdAt: { type: Date, default: Date.now }
});

const Invoice = mongoose.model('Invoice', InvoiceSchema);

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

// Update Invoice (Admin: all, User: only paymentRequest)
app.patch('/api/invoices/:id', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;
        const { status, paymentRequest } = req.body;
        const isAdmin = req.user.role === 'admin';

        // 1. Check if invoice exists
        const invoice = await Invoice.findById(id);
        if (!invoice) {
            return res.status(404).json({ success: false, message: "Không tìm thấy hóa đơn" });
        }

        const updateData = {};

        // 2. Logic for Admin
        if (isAdmin) {
            if (status) {
                if (!['pending', 'paid'].includes(status)) {
                    return res.status(400).json({ success: false, message: "Trạng thái không hợp lệ" });
                }
                updateData.status = status;
                // Nếu Admin xác nhận Đã thanh toán, tự động tắt yêu cầu xác nhận của cư dân
                if (status === 'paid') updateData.paymentRequest = false;
            }
            if (paymentRequest !== undefined) {
                updateData.paymentRequest = paymentRequest;
            }
        }
        // 3. Logic for Resident (User)
        else {
            // Check if this invoice belongs to the resident's room
            // (Optional security check: search for room matching user's phone)
            // For now, allow setting paymentRequest only
            if (paymentRequest !== undefined) {
                updateData.paymentRequest = paymentRequest;
            } else if (status) {
                return res.status(403).json({ success: false, message: "Bạn không có quyền thay đổi trạng thái thanh toán. Vui lòng liên hệ Admin." });
            }
        }

        const updatedInvoice = await Invoice.findByIdAndUpdate(id, updateData, { new: true });
        res.json({ success: true, message: "Cập nhật thành công", data: updatedInvoice });

    } catch (err) {
        console.error("Update Invoice Error:", err);
        res.status(500).json({ success: false, message: "Lỗi hệ thống khi cập nhật hóa đơn" });
    }
});

// ==================== INVOICE ROUTES ====================

// Get all invoices (Admin) or personal invoices (User)
app.get('/api/invoices', authenticateToken, async (req, res) => {
    try {
        let query = {};
        if (req.user.role !== 'admin') {
            // Cư dân chỉ xem được hóa đơn của phòng mình (dựa trên SĐT đăng nhập)
            // Lưu ý: Sẽ cần logic để khớp roomId của cư dân
            const phone = req.user.phone;
            // Tìm phòng có cư dân này
            const apartmentRecord = await ApartmentData.findOne().sort({ updatedAt: -1 });
            if (apartmentRecord) {
                const myRoom = apartmentRecord.data.find(room =>
                    room.residents && room.residents.some(r => r.phoneLogin === phone)
                );
                if (myRoom) {
                    query = { roomId: myRoom.id };
                } else {
                    return res.json({ success: true, data: [] });
                }
            }
        }

        const invoices = await Invoice.find(query).sort({ year: -1, month: -1 });
        res.json({ success: true, data: invoices });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Lỗi lấy dữ liệu hóa đơn' });
    }
});

// Create or Update Invoice (Admin only)
app.post('/api/invoices', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'admin') {
            return res.status(403).json({ success: false, message: 'Bạn không có quyền' });
        }

        const invoiceData = req.body;
        const { roomId, month, year } = invoiceData;

        // Upsert hóa đơn theo Phòng + Tháng + Năm
        const result = await Invoice.findOneAndUpdate(
            { roomId, month, year },
            { ...invoiceData },
            { upsert: true, new: true }
        );

        res.json({ success: true, message: 'Đã cập nhật hóa đơn thành công', data: result });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Lỗi lưu hóa đơn' });
    }
});



// Delete invoice (Admin only)
app.delete('/api/invoices/:id', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'admin') return res.status(403).json({ success: false });
        await Invoice.findByIdAndDelete(req.params.id);
        res.json({ success: true, message: 'Đã xóa hóa đơn' });
    } catch (error) {
        res.status(500).json({ success: false });
    }
});

// Reset toàn bộ hệ thống (Admin only)
app.post('/api/system/reset', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'admin') {
            return res.status(403).json({ success: false, message: 'Bạn không có quyền này' });
        }

        // 1. Xóa sạch dữ liệu căn hộ/cư dân
        await ApartmentData.deleteMany({});

        // 2. Xóa tất cả tài khoản người dùng NGOẠI TRỪ Admin đang thực hiện lệnh này
        const currentAdminId = req.user.id;
        await User.deleteMany({ _id: { $ne: currentAdminId } });

        res.json({
            success: true,
            message: 'Hệ thống đã được reset sạch sẽ. Tất cả cư dân và tài khoản (ngoại trừ bạn) đã bị xóa vĩnh viễn.'
        });
    } catch (error) {
        console.error('Reset error:', error);
        res.status(500).json({ success: false, message: 'Lỗi server khi reset dữ liệu' });
    }
});

// ==================== SYSTEM & USER MANAGEMENT ====================

// Update user account (Admin only)
app.patch('/api/users/:oldPhone', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'admin') {
            return res.status(403).json({ success: false, message: 'Bạn không có quyền này' });
        }

        const { oldPhone } = req.params;
        const { name, phone, email } = req.body;

        // Tìm user theo SĐT cũ
        const user = await User.findOne({ phone: oldPhone });
        if (!user) {
            return res.status(404).json({ success: false, message: 'Không tìm thấy tài khoản để cập nhật' });
        }

        // Cập nhật thông tin
        if (name) user.name = name;
        if (email !== undefined) user.email = email;
        if (phone && phone !== oldPhone) {
            // Kiểm tra SĐT mới đã có ai dùng chưa
            const phoneExists = await User.findOne({ phone });
            if (phoneExists) {
                return res.status(400).json({ success: false, message: 'Số điện thoại mới đã được sử dụng bởi một tài khoản khác' });
            }
            user.phone = phone;
        }

        await user.save();
        res.json({ success: true, message: 'Đã cập nhật tài khoản thành công', user: { name: user.name, phone: user.phone, email: user.email } });
    } catch (error) {
        console.error('Update user error:', error);
        res.status(500).json({ success: false, message: 'Lỗi server khi cập nhật tài khoản' });
    }
});

// Delete user account (Admin only)
app.delete('/api/users/:phone', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'admin') return res.status(403).json({ success: false });
        const { phone } = req.params;
        const result = await User.findOneAndDelete({ phone });
        if (!result) {
            return res.status(404).json({ success: false, message: 'Không tìm thấy tài khoản để xóa' });
        }
        res.json({ success: true, message: 'Đã xóa tài khoản thành công' });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Lỗi server khi xóa tài khoản' });
    }
});

// Reset toàn bộ hệ thống (Admin only)
app.post('/api/system/reset', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'admin') return res.status(403).json({ success: false });
        await ApartmentData.deleteMany({});
        await Invoice.deleteMany({}); // Xóa luôn cả hóa đơn khi reset
        const currentAdminId = req.user.id;
        await User.deleteMany({ _id: { $ne: currentAdminId } });
        res.json({ success: true, message: 'Hệ thống đã được reset sạch sẽ' });
    } catch (error) {
        res.status(500).json({ success: false });
    }
});

// ==================== START SERVER ====================

app.listen(PORT, () => {
    console.log(`🚀 Server is running on http://localhost:${PORT}`);
});
