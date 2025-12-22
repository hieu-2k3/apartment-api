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
app.use(express.json({ limit: '50mb' })); // Tăng giới hạn upload lên 50MB
app.use(express.urlencoded({ limit: '50mb', extended: true }));

// ... (existing code)

// ==================== ANNOUNCEMENT ROUTES ====================

const AnnouncementSchema = new mongoose.Schema({
    title: { type: String, required: true },
    content: { type: String, required: true },
    type: { type: String, enum: ['normal', 'urgent', 'event'], default: 'normal' },
    mediaType: { type: String, enum: ['image', 'video', 'none'], default: 'none' },
    mediaUrl: { type: String, default: "" }, // Base64 string
    createdBy: { type: String, default: 'Admin' },
    createdAt: { type: Date, default: Date.now }
});

const Announcement = mongoose.model('Announcement', AnnouncementSchema);

// Get all announcements (Public for authenticated users)
app.get('/api/announcements', authenticateToken, async (req, res) => {
    try {
        // Lấy 10 thông báo mới nhất
        const announcements = await Announcement.find().sort({ createdAt: -1 }).limit(10);
        res.json({ success: true, data: announcements });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Lỗi lấy thông báo' });
    }
});

// Create announcement (Admin only)
app.post('/api/announcements', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'admin') {
            return res.status(403).json({ success: false, message: 'Bạn không có quyền' });
        }

        const { title, content, type, mediaType, mediaUrl } = req.body;
        const newAnnouncement = new Announcement({
            title,
            content,
            type: type || 'normal',
            mediaType: mediaType || 'none',
            mediaUrl: mediaUrl || "",
            createdBy: req.user.name || "Admin"
        });

        await newAnnouncement.save();
        res.status(201).json({ success: true, message: 'Đã tạo thông báo', data: newAnnouncement });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Lỗi tạo thông báo' });
    }
});
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

const MaintenanceSchema = new mongoose.Schema({
    roomId: { type: String, required: true },
    roomName: { type: String, required: true },
    senderName: { type: String, required: true },
    phone: { type: String, required: true },
    title: { type: String, required: true },
    type: { type: String, enum: ['maintenance', 'feedback'], default: 'maintenance' },
    description: { type: String, required: true },
    status: { type: String, enum: ['pending', 'in-progress', 'completed', 'cancelled'], default: 'pending' },
    priority: { type: String, enum: ['low', 'medium', 'high'], default: 'medium' },
    note: { type: String, default: "" }, // Admin note
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});

const Maintenance = mongoose.model('Maintenance', MaintenanceSchema);

const ContractSchema = new mongoose.Schema({
    roomId: { type: String, required: true },
    roomName: { type: String, required: true },
    tenantName: { type: String, required: true },
    tenantPhone: { type: String, required: true },
    tenantIdCard: { type: String, default: "" },

    // Financial information
    monthlyRent: { type: Number, required: true },
    deposit: { type: Number, required: true },
    depositPaid: { type: Boolean, default: false },
    depositDate: { type: Date, default: null },

    // Contract duration
    startDate: { type: Date, required: true },
    endDate: { type: Date, required: true },
    duration: { type: Number, required: true }, // in months

    // Status
    status: { type: String, enum: ['active', 'expired', 'terminated'], default: 'active' },

    // Special terms
    terms: { type: [String], default: [] },

    // File attachment (base64 or URL)
    contractFile: { type: String, default: "" },

    // Metadata
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now },
    createdBy: { type: String, default: "" }
});

const Contract = mongoose.model('Contract', ContractSchema);

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

// Register new user (Simple flow)
app.post('/api/register', async (req, res) => {
    try {
        if (mongoose.connection.readyState !== 1) {
            return res.status(503).json({ success: false, message: 'Server đang bận, vui lòng thử lại sau.' });
        }

        const { name, phone, email, password, adminCode } = req.body;

        if (!name || !phone || !password) {
            return res.status(400).json({ success: false, message: 'Vui lòng nhập đầy đủ: Họ tên, Số điện thoại và Mật khẩu' });
        }

        // 1. Kiểm tra SĐT đã tồn tại chưa
        const existingUser = await User.findOne({ phone: phone.trim() });
        if (existingUser) {
            return res.status(400).json({ success: false, message: 'Số điện thoại này đã được đăng ký tài khoản' });
        }

        // 2. Phân loại Role
        const role = (adminCode === 'ADMIN2025') ? 'admin' : 'user';

        // 3. Tạo tài khoản
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({
            name: name.trim(),
            phone: phone.trim(),
            email: email ? email.trim() : "",
            password: hashedPassword,
            role: role
        });

        await newUser.save();

        const token = jwt.sign(
            { id: newUser._id, phone: newUser.phone, name: newUser.name, role: newUser.role },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.status(201).json({
            success: true,
            message: role === 'admin' ? 'Đăng ký Admin thành công' : 'Đăng ký tài khoản thành công!',
            token,
            user: { id: newUser._id, name: newUser.name, phone: newUser.phone, role: newUser.role }
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

// Reset password (simple flow)
app.post('/api/forgot-password', async (req, res) => {
    try {
        const { phone, newPassword } = req.body;

        if (!phone || !newPassword) {
            return res.status(400).json({ success: false, message: 'Vui lòng nhập đầy đủ SĐT và Mật khẩu mới' });
        }

        // 1. Tìm User
        const user = await User.findOne({ phone: phone.trim() });
        if (!user) {
            return res.status(404).json({ success: false, message: 'Không tìm thấy tài khoản với số điện thoại này' });
        }

        // 2. Cập nhật mật khẩu
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        user.password = hashedPassword;
        await user.save();

        res.json({ success: true, message: 'Đặt lại mật khẩu thành công. Vui lòng đăng nhập lại.' });

    } catch (error) {
        console.error('Reset password error:', error);
        res.status(500).json({ success: false, message: 'Lỗi server khi đặt lại mật khẩu' });
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
// ==================== USER MANAGEMENT ROUTES ====================

// Get all unassigned users (Admin only)
app.get('/api/users/unassigned', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'admin') {
            return res.status(403).json({ success: false, message: 'Chỉ Admin mới có quyền này' });
        }

        // 1. Lấy tất cả người dùng bình thường
        const allUsers = await User.find({ role: 'user' }).lean();

        // 2. Lấy dữ liệu tòa nhà hiện tại để xem ai đã có phòng
        const record = await ApartmentData.findOne().sort({ updatedAt: -1 }).lean();

        if (!record) {
            return res.json({ success: true, data: allUsers });
        }

        // Tạo tập hợp các SĐT đã có phòng
        const assignedPhones = new Set();
        record.data.forEach(room => {
            if (room.residents) {
                room.residents.forEach(res => {
                    if (res.phoneLogin) assignedPhones.add(res.phoneLogin.trim());
                    if (res.phone) assignedPhones.add(res.phone.trim());
                });
            }
        });

        // Lọc ra những người dùng chưa có SĐT trong bất kỳ phòng nào
        const unassignedUsers = allUsers.filter(user => !assignedPhones.has(user.phone.trim()));

        res.json({ success: true, data: unassignedUsers });
    } catch (error) {
        console.error('Error fetching unassigned users:', error);
        res.status(500).json({ success: false, message: 'Lỗi lấy danh sách người dùng' });
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

// ==================== MAINTENANCE & FEEDBACK ROUTES ====================

// Get all requests (Admin) or user requests (User)
app.get('/api/maintenance', authenticateToken, async (req, res) => {
    console.log(`Maintenance fetch requested by user: ${req.user.phone}, role: ${req.user.role}`);
    try {
        let query = {};
        if (req.user.role !== 'admin') {
            query = { phone: req.user.phone };
        }
        const requests = await Maintenance.find(query).sort({ createdAt: -1 });
        res.json({ success: true, data: requests });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Lỗi lấy dữ liệu phản hồi' });
    }
});

// Create new request
app.post('/api/maintenance', authenticateToken, async (req, res) => {
    try {
        const { roomId, roomName, senderName, title, type, description, priority } = req.body;

        const newRequest = new Maintenance({
            roomId,
            roomName,
            senderName,
            phone: req.user.phone,
            title,
            type: type || 'maintenance',
            description,
            priority: priority || 'medium'
        });

        await newRequest.save();
        res.status(201).json({ success: true, message: 'Gửi yêu cầu thành công', data: newRequest });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Lỗi khi gửi yêu cầu' });
    }
});

// Update request status (Admin) or content (User)
app.patch('/api/maintenance/:id', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;
        const isAdmin = req.user.role === 'admin';
        const maintenance = await Maintenance.findById(id);

        if (!maintenance) {
            return res.status(404).json({ success: false, message: 'Không tìm thấy yêu cầu' });
        }

        if (!isAdmin && maintenance.phone !== req.user.phone) {
            return res.status(403).json({ success: false, message: 'Bạn không có quyền' });
        }

        const updates = req.body;
        updates.updatedAt = new Date();

        // Prevent users from changing status to anything other than cancelled
        if (!isAdmin && updates.status && updates.status !== 'cancelled') {
            delete updates.status;
        }

        const updated = await Maintenance.findByIdAndUpdate(id, updates, { new: true });
        res.json({ success: true, message: 'Cập nhật thành công', data: updated });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Lỗi cập nhật yêu cầu' });
    }
});

// Delete request (Admin only)
app.delete('/api/maintenance/:id', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'admin') return res.status(403).json({ success: false });
        await Maintenance.findByIdAndDelete(req.params.id);
        res.json({ success: true, message: 'Đã xóa yêu cầu' });
    } catch (error) {
        res.status(500).json({ success: false });
    }
});



// Delete announcement (Admin only)
app.delete('/api/announcements/:id', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'admin') return res.status(403).json({ success: false });
        await Announcement.findByIdAndDelete(req.params.id);
        res.json({ success: true, message: 'Đã xóa thông báo' });
    } catch (error) {
        res.status(500).json({ success: false });
    }
});

// ==================== MARKETPLACE ROUTES ====================

const MarketItemSchema = new mongoose.Schema({
    title: { type: String, required: true },
    price: { type: Number, required: true },
    description: String,
    contactPhone: String,
    roomName: String,
    image: String, // Base64
    createdBy: String, // User ID
    createdAt: { type: Date, default: Date.now }
});

const MarketItem = mongoose.model('MarketItem', MarketItemSchema);

// Get all market items
app.get('/api/market', authenticateToken, async (req, res) => {
    try {
        const items = await MarketItem.find().sort({ createdAt: -1 });
        res.json({ success: true, data: items });
    } catch (err) {
        res.status(500).json({ success: false });
    }
});

// Post new item
app.post('/api/market', authenticateToken, async (req, res) => {
    try {
        const { title, price, description, contactPhone, image, roomName } = req.body;
        const newItem = new MarketItem({
            title,
            price,
            description,
            contactPhone,
            roomName: roomName || 'Admin',
            image,
            createdBy: req.user.id
        });
        await newItem.save();
        res.json({ success: true, message: 'Đã đăng tin thành công' });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Lỗi đăng tin' });
    }
});

// Delete item (Owner or Admin)
app.delete('/api/market/:id', authenticateToken, async (req, res) => {
    try {
        const item = await MarketItem.findById(req.params.id);
        if (!item) return res.status(404).json({ success: false });

        // Check permission: Admin or Owner
        if (req.user.role !== 'admin' && item.createdBy !== req.user.id) {
            return res.status(403).json({ success: false, message: 'Không có quyền xóa tin này' });
        }

        await MarketItem.findByIdAndDelete(req.params.id);
        res.json({ success: true, message: 'Đã xóa tin' });
    } catch (err) {
        res.status(500).json({ success: false });
    }
});

// ==================== CONTRACT ROUTES ====================

// Get all contracts (Admin) or user's contract (User)
app.get('/api/contracts', authenticateToken, async (req, res) => {
    try {
        let query = {};

        if (req.user.role !== 'admin') {
            // Logic cho User thường:

            // 1. Lấy thông tin tòa nhà mới nhất để tìm phòng của user
            // Vì ApartmentData lưu toàn bộ state trong field 'data' của 1 document
            const buildingDoc = await ApartmentData.findOne().sort({ updatedAt: -1 });
            let userRoomId = null;

            if (buildingDoc && buildingDoc.data && Array.isArray(buildingDoc.data)) {
                // Normalize user phone
                const myPhone = req.user.phone.replace(/\D/g, '');

                // Tìm phòng trong mảng data
                const foundRoom = buildingDoc.data.find(room =>
                    room.residents && Array.isArray(room.residents) &&
                    room.residents.some(r => {
                        const rPhone = (r.phoneLogin || '').replace(/\D/g, '');
                        return rPhone === myPhone;
                    })
                );

                if (foundRoom) {
                    userRoomId = foundRoom.id;
                }
            }

            if (userRoomId) {
                // Logic hiển thị nâng cao:
                // 1. Xem hợp đồng Active của phòng hiện tại (Dành cho cả chủ và roommate)
                // 2. Xem lịch sử hợp đồng của chính mình (Đã kết thúc/hủy) - Ở bất kỳ phòng nào
                // 3. Xem hợp đồng của chính mình tại phòng hiện tại (Bao gồm cả đang chờ, active...)

                // NGĂN CHẶN: Xem hợp đồng Active cũ ở phòng khác (khi user đã chuyển phòng nhưng tên vẫn trên HĐ cũ)
                query = {
                    $or: [
                        { roomId: userRoomId, status: 'active' },
                        { tenantPhone: req.user.phone, status: { $ne: 'active' } },
                        { tenantPhone: req.user.phone, roomId: userRoomId }
                    ]
                };
            } else {
                // Chưa gán phòng -> Chỉ xem HĐ của chính mình nhưng PHẢI KHÔNG ĐƯỢC LÀ ACTIVE của phòng khác?
                // Nếu chưa gán phòng, logic User chuyển đi (rời P1) -> Thành "chưa gán".
                // Lúc này User vẫn thấy HĐ Active P1? -> User nói là "Không muốn thấy".
                // Vậy nếu chưa gán phòng, chỉ cho xem lịch sử (non-active).
                query = {
                    tenantPhone: req.user.phone,
                    status: { $ne: 'active' }
                };
            }
        }

        const contracts = await Contract.find(query).sort({ createdAt: -1 });
        res.json({ success: true, data: contracts });
    } catch (error) {
        console.error("Error fetching contracts:", error);
        res.status(500).json({ success: false, message: 'Lỗi lấy danh sách hợp đồng' });
    }
});

// Get contract by room ID
app.get('/api/contracts/room/:roomId', authenticateToken, async (req, res) => {
    try {
        const contract = await Contract.findOne({
            roomId: req.params.roomId,
            status: 'active'
        });

        if (!contract) {
            return res.json({ success: true, data: null });
        }

        res.json({ success: true, data: contract });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Lỗi lấy hợp đồng' });
    }
});

// Create new contract (Admin only)
app.post('/api/contracts', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'admin') {
            return res.status(403).json({ success: false, message: 'Chỉ admin mới có quyền tạo hợp đồng' });
        }

        const {
            roomId, roomName, tenantName, tenantPhone, tenantIdCard,
            monthlyRent, deposit, depositPaid, depositDate,
            startDate, endDate, duration, terms, contractFile
        } = req.body;

        // Check if room already has an active contract
        const existingContract = await Contract.findOne({
            roomId,
            status: 'active'
        });

        if (existingContract) {
            return res.status(400).json({
                success: false,
                message: 'Phòng này đã có hợp đồng đang hoạt động'
            });
        }

        const newContract = new Contract({
            roomId, roomName, tenantName, tenantPhone, tenantIdCard,
            monthlyRent, deposit, depositPaid,
            depositDate: depositPaid ? (depositDate || new Date()) : null,
            startDate, endDate, duration,
            terms: terms || [],
            contractFile: contractFile || "",
            createdBy: req.user.phone
        });

        await newContract.save();
        res.status(201).json({
            success: true,
            message: 'Đã tạo hợp đồng thành công',
            data: newContract
        });
    } catch (error) {
        console.error('Error creating contract:', error);
        res.status(500).json({ success: false, message: 'Lỗi tạo hợp đồng' });
    }
});

// Update contract (Admin only)
app.patch('/api/contracts/:id', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'admin') {
            return res.status(403).json({ success: false, message: 'Chỉ admin mới có quyền sửa hợp đồng' });
        }

        const updates = { ...req.body, updatedAt: new Date() };
        const contract = await Contract.findByIdAndUpdate(
            req.params.id,
            updates,
            { new: true }
        );

        if (!contract) {
            return res.status(404).json({ success: false, message: 'Không tìm thấy hợp đồng' });
        }

        res.json({ success: true, message: 'Đã cập nhật hợp đồng', data: contract });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Lỗi cập nhật hợp đồng' });
    }
});

// Terminate contract (Admin only)
app.delete('/api/contracts/:id', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'admin') {
            return res.status(403).json({ success: false, message: 'Chỉ admin mới có quyền xóa hợp đồng' });
        }

        const contract = await Contract.findByIdAndUpdate(
            req.params.id,
            { status: 'terminated', updatedAt: new Date() },
            { new: true }
        );

        if (!contract) {
            return res.status(404).json({ success: false, message: 'Không tìm thấy hợp đồng' });
        }

        res.json({ success: true, message: 'Đã kết thúc hợp đồng' });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Lỗi kết thúc hợp đồng' });
    }
});

// Get contracts expiring soon (Admin only)
app.get('/api/contracts/expiring/:days', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'admin') {
            return res.status(403).json({ success: false });
        }

        const days = parseInt(req.params.days) || 30;
        const futureDate = new Date();
        futureDate.setDate(futureDate.getDate() + days);

        const expiringContracts = await Contract.find({
            status: 'active',
            endDate: { $lte: futureDate, $gte: new Date() }
        }).sort({ endDate: 1 });

        res.json({ success: true, data: expiringContracts });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Lỗi lấy danh sách hợp đồng sắp hết hạn' });
    }
});

// Cleanup User & Related Data (Admin only) - SUPER DELETE
app.delete('/api/cleanup-user/:phone', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'admin') {
            return res.status(403).json({ success: false, message: 'Chỉ admin mới có quyền thực hiện' });
        }

        const rawPhone = req.params.phone;
        const digits = rawPhone.replace(/\D/g, '');
        const corePhone = digits.length > 9 ? digits.slice(-9) : digits;

        console.log(`Cleanup Request for: ${rawPhone} (Core: ${corePhone})`);

        // 1. Identify Contracts to delete
        const allContracts = await Contract.find({
            tenantPhone: { $regex: corePhone + '$' }
        });

        const contractsToDelete = [];
        let keptActiveContracts = 0;

        // Lấy Building Data một lần để check
        const buildingDoc = await ApartmentData.findOne().sort({ updatedAt: -1 });
        const roomsData = buildingDoc ? buildingDoc.data : [];

        for (const contract of allContracts) {
            if (contract.status !== 'active') {
                // HĐ cũ/đã hủy -> Xóa luôn
                contractsToDelete.push(contract._id);
            } else {
                // HĐ Active -> Check xem phòng còn ai không
                let roomHasOtherPeople = false;

                if (roomsData) {
                    const room = roomsData.find(r => r.id === contract.roomId);
                    if (room && room.residents && Array.isArray(room.residents)) {
                        // Logic: ApartmentData chưa được update (vẫn còn user này).
                        // Nên nếu count > 1 nghĩa là còn người khác.
                        // Nếu count == 1 (chỉ còn user này) thì coi như trống.
                        // Tuy nhiên, để an toàn hơn, ta check xem có resident nào KHÁC user này ko.
                        const otherResidents = room.residents.filter(r => {
                            const rPhone = (r.phoneLogin || '').replace(/\D/g, '');
                            return !rPhone.endsWith(corePhone);
                        });

                        if (otherResidents.length > 0) {
                            roomHasOtherPeople = true;
                        }
                    }
                }

                if (roomHasOtherPeople) {
                    console.log(`Keeping active contract ${contract._id} because room ${contract.roomId} has other residents.`);
                    keptActiveContracts++;
                } else {
                    console.log(`Deleting active contract ${contract._id} because room becomes empty.`);
                    contractsToDelete.push(contract._id);
                }
            }
        }

        // 2. Perform Deletion
        const userDeleteRes = await User.deleteMany({
            phone: { $regex: corePhone + '$' }
        });

        let contractDeleteCount = 0;
        if (contractsToDelete.length > 0) {
            const deleteResult = await Contract.deleteMany({
                _id: { $in: contractsToDelete }
            });
            contractDeleteCount = deleteResult.deletedCount;
        }

        res.json({
            success: true,
            message: `Dọn dẹp xong: Xóa ${userDeleteRes.deletedCount} user, ${contractDeleteCount} hợp đồng. (Giữ lại ${keptActiveContracts} hợp đồng đang Active vì còn người ở).`,
            details: {
                usersDeleted: userDeleteRes.deletedCount,
                contractsDeleted: contractDeleteCount,
                activeContractsKept: keptActiveContracts
            }
        });

    } catch (error) {
        console.error('Error cleanup user:', error);
        res.status(500).json({ success: false, message: 'Lỗi dọn dẹp dữ liệu người dùng' });
    }
});

// Reset toàn bộ hệ thống (Toàn diện)
app.post('/api/system/reset', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'admin') {
            return res.status(403).json({ success: false, message: 'Bạn không có quyền thực hiện hành động này' });
        }

        const currentAdminId = req.user.id;

        // Xóa sạch tất cả các bảng dữ liệu
        await Promise.all([
            ApartmentData.deleteMany({}),
            Invoice.deleteMany({}),
            Maintenance.deleteMany({}),
            Announcement.deleteMany({}),
            MarketItem.deleteMany({}),
            Contract.deleteMany({}),
            // Xóa tất cả user ngoại trừ admin hiện tại
            User.deleteMany({ _id: { $ne: currentAdminId } })
        ]);

        console.log(`System Reset initiated by Admin ID: ${currentAdminId}`);

        res.json({
            success: true,
            message: 'Hệ thống đã được dọn dẹp hoàn toàn! Mọi cư dân, hóa đơn, thông báo và bài đăng đã bị xóa. Chỉ tài khoản Admin của bạn được giữ lại.'
        });
    } catch (error) {
        console.error('Full System Reset Error:', error);
        res.status(500).json({ success: false, message: 'Đã có lỗi xảy ra trong quá trình reset hệ thống' });
    }
});

// ==================== START SERVER ====================

app.listen(PORT, () => {
    console.log(`🚀 Server is running on http://localhost:${PORT}`);
});
