require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const http = require('http');
const { Server } = require('socket.io');
const { Low } = require('lowdb');
const { JSONFile } = require('lowdb/node');
const multer = require('multer');
const { v4: uuidv4 } = require('uuid');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const fs = require('fs');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'chatrm-secret';

const adapter = new JSONFile(path.join(__dirname, 'db.json'));
const db = new Low(adapter);

const uploadDir = path.join(__dirname, 'public', 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

const fileStorage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, Date.now() + '-' + uuidv4().slice(0, 8) + ext);
  }
});

const upload = multer({
  storage: fileStorage,
  limits: { fileSize: 50 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowed = /jpeg|jpg|png|gif|webp|mp4|webm|mov|avi|zip|rar|7z|pdf|txt|js|json|html|css|md/;
    if (allowed.test(path.extname(file.originalname).toLowerCase())) return cb(null, true);
    cb(new Error('File type tidak didukung'));
  }
});

const avatarUpload = multer({
  storage: fileStorage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowed = /jpeg|jpg|png|gif|webp/;
    if (allowed.test(path.extname(file.originalname).toLowerCase())) return cb(null, true);
    cb(new Error('Hanya gambar'));
  }
});

function getIP(req) {
  return (req.headers['x-forwarded-for'] || req.connection.remoteAddress || '')
    .split(',')[0].trim().replace('::ffff:', '');
}

app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true }));

app.use(async (req, res, next) => {
  try {
    await db.read();
    const ip = getIP(req);
    const banned = (db.data.banned_ips || []).find(b => b.ip === ip);
    if (banned) {
      return res.status(403).send('<html><head><title>Akses Diblokir</title><style>body{font-family:sans-serif;background:#14171c;color:#e8eaf0;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;text-align:center;padding:20px}.box{max-width:500px}h1{color:#c92a2a;margin-bottom:12px}p{color:#a0a8b8;line-height:1.6}</style></head><body><div class="box"><h1>🚫 Akses Diblokir</h1><p>IP Anda (' + ip + ') telah diblokir oleh admin.</p><p style="font-size:0.8rem;margin-top:12px;">Alasan: ' + (banned.reason || 'Tidak disebutkan') + '</p></div></body></html>');
    }
  } catch (e) {}
  next();
});

app.use(async (req, res, next) => {
  if (req.path === '/' && req.method === 'GET') {
    try {
      await db.read();
      db.data.stats.visitors = (db.data.stats.visitors || 0) + 1;
      await db.write();
    } catch (e) {}
  }
  next();
});

app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(uploadDir));

function authMiddleware(req, res, next) {
  const token = req.header('Authorization')?.replace('Bearer ', '') || req.query.token;
  if (!token) return res.status(401).json({ error: 'Login diperlukan' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (err) {
    res.status(401).json({ error: 'Token tidak valid' });
  }
}

function adminMiddleware(req, res, next) {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Akses khusus admin' });
  }
  next();
}

async function initDB() {
  await db.read();
  if (!db.data) db.data = {};
  db.data.users = db.data.users || [];
  db.data.chats = db.data.chats || [];
  db.data.uploads = db.data.uploads || [];
  db.data.projects = db.data.projects || [];
  db.data.banned_ips = db.data.banned_ips || [];
  db.data.stats = db.data.stats || { visitors: 0 };

  const adminEmail = process.env.ADMIN_EMAIL;
  const adminPassword = process.env.ADMIN_PASSWORD;
  const adminUsername = process.env.ADMIN_USERNAME || 'admin';

  if (adminEmail && adminPassword) {
    const existingAdmin = db.data.users.find(u => u.email.toLowerCase() === adminEmail.toLowerCase());
    if (!existingAdmin) {
      const hashed = await bcrypt.hash(adminPassword, 10);
      db.data.users.push({
        id: uuidv4(),
        username: adminUsername,
        email: adminEmail,
        password: hashed,
        bio: 'Administrator ChatRm',
        avatar: '',
        role: 'admin',
        joinedAt: new Date().toISOString(),
        reputation: 999
      });
      console.log('✅ Admin default dibuat:', adminEmail);
    } else if (existingAdmin.role !== 'admin') {
      existingAdmin.role = 'admin';
      console.log('✅ Role admin dipastikan:', adminEmail);
    }
  }

  await db.write();
  console.log('✅ Database siap');
}
initDB();

app.post('/api/auth/register', async (req, res) => {
  await db.read();
  const { username, email, password, bio } = req.body;
  if (!username || !email || !password)
    return res.status(400).json({ error: 'Semua field wajib diisi' });
  if (username.length < 3 || username.length > 20)
    return res.status(400).json({ error: 'Username 3-20 karakter' });
  if (!/^[a-zA-Z0-9_]+$/.test(username))
    return res.status(400).json({ error: 'Username hanya huruf, angka, underscore' });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
    return res.status(400).json({ error: 'Format email tidak valid' });
  if (password.length < 6)
    return res.status(400).json({ error: 'Password minimal 6 karakter' });
  if (db.data.users.find(u => u.username.toLowerCase() === username.toLowerCase()))
    return res.status(400).json({ error: 'Username sudah dipakai' });
  if (db.data.users.find(u => u.email.toLowerCase() === email.toLowerCase()))
    return res.status(400).json({ error: 'Email sudah terdaftar' });

  const hashed = await bcrypt.hash(password, 10);
  const user = {
    id: uuidv4(), username, email, password: hashed,
    bio: bio || '', avatar: '', role: 'user',
    joinedAt: new Date().toISOString(), reputation: 0
  };
  db.data.users.push(user);
  await db.write();

  const token = jwt.sign(
    { id: user.id, username, email, role: 'user' },
    JWT_SECRET,
    { expiresIn: '30d' }
  );

  res.status(201).json({
    token,
    user: {
      id: user.id, username, email, bio: user.bio,
      avatar: user.avatar, role: user.role,
      joinedAt: user.joinedAt, reputation: user.reputation
    }
  });
});

app.post('/api/auth/login', async (req, res) => {
  await db.read();
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email & password wajib diisi' });

  const isAdminCreds =
    process.env.ADMIN_EMAIL &&
    process.env.ADMIN_PASSWORD &&
    email.toLowerCase() === process.env.ADMIN_EMAIL.toLowerCase() &&
    password === process.env.ADMIN_PASSWORD;

  if (isAdminCreds) {
    let admin = db.data.users.find(u => u.email.toLowerCase() === process.env.ADMIN_EMAIL.toLowerCase());
    if (!admin) {
      const hashed = await bcrypt.hash(process.env.ADMIN_PASSWORD, 10);
      admin = {
        id: uuidv4(),
        username: process.env.ADMIN_USERNAME || 'admin',
        email: process.env.ADMIN_EMAIL,
        password: hashed,
        bio: 'Administrator ChatRm',
        avatar: '', role: 'admin',
        joinedAt: new Date().toISOString(),
        reputation: 999
      };
      db.data.users.push(admin);
      await db.write();
    }

    const token = jwt.sign(
      { id: admin.id, username: admin.username, email: admin.email, role: 'admin' },
      JWT_SECRET, { expiresIn: '30d' }
    );

    return res.json({
      token,
      user: {
        id: admin.id, username: admin.username, email: admin.email,
        bio: admin.bio, avatar: admin.avatar, role: 'admin',
        joinedAt: admin.joinedAt, reputation: admin.reputation
      }
    });
  }

  const user = db.data.users.find(u =>
    u.email.toLowerCase() === email.toLowerCase() ||
    u.username.toLowerCase() === email.toLowerCase()
  );
  if (!user) return res.status(401).json({ error: 'Akun tidak ditemukan' });

  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.status(401).json({ error: 'Password salah' });

  const token = jwt.sign(
    { id: user.id, username: user.username, email: user.email, role: user.role || 'user' },
    JWT_SECRET, { expiresIn: '30d' }
  );

  res.json({
    token,
    user: {
      id: user.id, username: user.username, email: user.email,
      bio: user.bio, avatar: user.avatar, role: user.role || 'user',
      joinedAt: user.joinedAt, reputation: user.reputation
    }
  });
});

app.get('/api/auth/me', authMiddleware, async (req, res) => {
  await db.read();
  const user = db.data.users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: 'User tidak ditemukan' });
  res.json({
    id: user.id, username: user.username, email: user.email,
    bio: user.bio, avatar: user.avatar, role: user.role || 'user',
    joinedAt: user.joinedAt, reputation: user.reputation
  });
});

app.put('/api/auth/profile', authMiddleware, async (req, res) => {
  await db.read();
  const user = db.data.users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: 'User tidak ditemukan' });

  const { username, bio } = req.body;

  if (username) {
    if (username.length < 3 || username.length > 20)
      return res.status(400).json({ error: 'Username 3-20 karakter' });
    if (!/^[a-zA-Z0-9_]+$/.test(username))
      return res.status(400).json({ error: 'Username hanya huruf, angka, underscore' });
    const taken = db.data.users.find(u => u.id !== user.id && u.username.toLowerCase() === username.toLowerCase());
    if (taken) return res.status(400).json({ error: 'Username sudah dipakai' });
    user.username = username;
  }

  if (bio !== undefined) user.bio = String(bio).slice(0, 200);

  await db.write();
  res.json({
    id: user.id, username: user.username, email: user.email,
    bio: user.bio, avatar: user.avatar, role: user.role || 'user',
    joinedAt: user.joinedAt, reputation: user.reputation
  });
});

app.put('/api/auth/password', authMiddleware, async (req, res) => {
  await db.read();
  const user = db.data.users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: 'User tidak ditemukan' });

  const { oldPassword, newPassword } = req.body;
  if (!oldPassword || !newPassword)
    return res.status(400).json({ error: 'Password lama & baru wajib diisi' });
  if (newPassword.length < 6)
    return res.status(400).json({ error: 'Password baru minimal 6 karakter' });

  const match = await bcrypt.compare(oldPassword, user.password);
  if (!match) return res.status(401).json({ error: 'Password lama salah' });

  user.password = await bcrypt.hash(newPassword, 10);
  await db.write();
  res.json({ success: true });
});

app.post('/api/auth/avatar', authMiddleware, avatarUpload.single('avatar'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'File tidak ditemukan' });
  await db.read();
  const user = db.data.users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: 'User tidak ditemukan' });
  user.avatar = '/uploads/' + req.file.filename;
  await db.write();
  res.json({ success: true, avatar: user.avatar });
});

app.get('/api/admin/users', authMiddleware, adminMiddleware, async (req, res) => {
  await db.read();
  const users = db.data.users.map(u => ({
    id: u.id, username: u.username, email: u.email,
    role: u.role || 'user', joinedAt: u.joinedAt
  }));
  res.json(users);
});

app.get('/api/admin/banned', authMiddleware, adminMiddleware, async (req, res) => {
  await db.read();
  res.json(db.data.banned_ips || []);
});

app.post('/api/admin/ban', authMiddleware, adminMiddleware, async (req, res) => {
  await db.read();
  const { ip, reason } = req.body;
  if (!ip) return res.status(400).json({ error: 'IP wajib diisi' });

  const existing = (db.data.banned_ips || []).find(b => b.ip === ip);
  if (existing) return res.status(400).json({ error: 'IP sudah diblokir' });

  db.data.banned_ips = db.data.banned_ips || [];
  db.data.banned_ips.push({
    ip,
    reason: reason || 'Tidak disebutkan',
    bannedAt: new Date().toISOString(),
    bannedBy: req.user.username
  });
  await db.write();
  res.json({ success: true });
});

app.delete('/api/admin/ban/:ip', authMiddleware, adminMiddleware, async (req, res) => {
  await db.read();
  const ip = req.params.ip;
  const idx = (db.data.banned_ips || []).findIndex(b => b.ip === ip);
  if (idx === -1) return res.status(404).json({ error: 'IP tidak ditemukan' });
  db.data.banned_ips.splice(idx, 1);
  await db.write();
  res.json({ success: true });
});

app.delete('/api/admin/chat/:id', authMiddleware, adminMiddleware, async (req, res) => {
  await db.read();
  const idx = db.data.chats.findIndex(c => c.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Pesan tidak ditemukan' });
  db.data.chats.splice(idx, 1);
  await db.write();
  io.emit('chat-deleted', { id: req.params.id });
  res.json({ success: true });
});

app.delete('/api/admin/chat', authMiddleware, adminMiddleware, async (req, res) => {
  await db.read();
  db.data.chats = [];
  await db.write();
  io.emit('chat-cleared');
  res.json({ success: true });
});

app.get('/api/admin/active-ips', authMiddleware, adminMiddleware, (req, res) => {
  const ips = [];
  for (const [id, socket] of io.sockets.sockets) {
    if (socket.user && socket.ip) {
      ips.push({ ip: socket.ip, username: socket.user.username, userId: socket.user.id, socketId: socket.id });
    }
  }
  res.json(ips);
});

app.get('/api/projects', async (req, res) => {
  await db.read();
  const { search, type, sort } = req.query;
  let projects = db.data.projects.slice();
  if (search) {
    const s = search.toLowerCase();
    projects = projects.filter(p =>
      p.title.toLowerCase().includes(s) ||
      p.description.toLowerCase().includes(s) ||
      p.tags.some(t => t.toLowerCase().includes(s))
    );
  }
  if (type && type !== 'all') projects = projects.filter(p => p.type === type);
  if (sort === 'popular') projects.sort((a, b) => (b.likes || 0) - (a.likes || 0));
  else if (sort === 'downloads') projects.sort((a, b) => (b.downloads || 0) - (a.downloads || 0));
  else projects.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));

  const enriched = projects.map(p => {
    const u = db.data.users.find(x => x.id === p.userId);
    return { ...p, author: u ? { username: u.username, avatar: u.avatar } : { username: 'Unknown', avatar: '' } };
  });
  res.json(enriched);
});

app.get('/api/projects/:id', async (req, res) => {
  await db.read();
  const p = db.data.projects.find(x => x.id === req.params.id);
  if (!p) return res.status(404).json({ error: 'Project tidak ditemukan' });
  const u = db.data.users.find(x => x.id === p.userId);
  res.json({ ...p, author: u ? { username: u.username, avatar: u.avatar, bio: u.bio } : null });
});

app.post('/api/projects', authMiddleware, async (req, res) => {
  await db.read();
  const user = db.data.users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: 'User tidak ditemukan' });
  const { title, description, type, sourceCode, demoUrl, tags, fileName, fileUrl, language } = req.body;
  if (!title || !description) return res.status(400).json({ error: 'Judul & deskripsi wajib diisi' });

  const project = {
    id: uuidv4(), userId: user.id,
    title: title.slice(0, 100),
    description: description.slice(0, 2000),
    type: type || 'other',
    sourceCode: sourceCode ? String(sourceCode).slice(0, 50000) : '',
    demoUrl: demoUrl ? String(demoUrl).slice(0, 500) : '',
    language: language || 'javascript',
    tags: Array.isArray(tags) ? tags.slice(0, 10).map(t => String(t).slice(0, 30)) : [],
    fileName: fileName || '', fileUrl: fileUrl || '',
    likes: 0, downloads: 0,
    createdAt: new Date().toISOString()
  };
  db.data.projects.push(project);
  user.reputation = (user.reputation || 0) + 5;
  await db.write();
  res.status(201).json(project);
});

app.post('/api/projects/:id/like', authMiddleware, async (req, res) => {
  await db.read();
  const p = db.data.projects.find(x => x.id === req.params.id);
  if (!p) return res.status(404).json({ error: 'Project tidak ditemukan' });
  p.likes = (p.likes || 0) + 1;
  await db.write();
  res.json({ success: true, likes: p.likes });
});

app.post('/api/projects/:id/download', async (req, res) => {
  await db.read();
  const p = db.data.projects.find(x => x.id === req.params.id);
  if (!p) return res.status(404).json({ error: 'Project tidak ditemukan' });
  p.downloads = (p.downloads || 0) + 1;
  await db.write();
  res.json({ success: true, downloads: p.downloads });
});

app.post('/api/upload', authMiddleware, upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'File tidak ditemukan' });
  await db.read();
  const fileData = {
    id: uuidv4(),
    filename: req.file.filename,
    originalName: req.file.originalname,
    size: req.file.size,
    mimetype: req.file.mimetype,
    url: '/uploads/' + req.file.filename,
    userId: req.user.id,
    uploadedAt: new Date().toISOString()
  };
  db.data.uploads.push(fileData);
  await db.write();
  res.json({ success: true, file: fileData });
});

app.get('/api/stats', async (req, res) => {
  await db.read();
  res.json({
    visitors: db.data.stats.visitors || 0,
    online: io.engine.clientsCount || 0,
    totalChats: db.data.chats.length,
    totalUploads: db.data.uploads.length,
    totalUsers: db.data.users.length,
    totalProjects: db.data.projects.length
  });
});

app.get('/api/chat/history', async (req, res) => {
  await db.read();
  res.json(db.data.chats.slice(-100));
});

io.use(async (socket, next) => {
  const token = socket.handshake.auth?.token;
  if (!token) return next(new Error('Login diperlukan'));
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    await db.read();
    const user = db.data.users.find(u => u.id === decoded.id);
    if (!user) return next(new Error('User tidak ditemukan'));
    socket.user = {
      id: user.id,
      username: user.username,
      avatar: user.avatar,
      role: user.role || 'user'
    };
    socket.ip = (socket.handshake.headers['x-forwarded-for'] || socket.handshake.address || '')
      .split(',')[0].trim().replace('::ffff:', '');
    next();
  } catch (err) {
    next(new Error('Token tidak valid'));
  }
});

io.on('connection', (socket) => {
  io.emit('online-count', io.engine.clientsCount);

  socket.on('send-message', async (data) => {
    const msg = {
      id: uuidv4(),
      type: 'user',
      userId: socket.user.id,
      username: socket.user.username,
      avatar: socket.user.avatar,
      role: socket.user.role,
      message: String(data.message || '').slice(0, 500),
      image: data.image || null,
      createdAt: new Date().toISOString()
    };
    await db.read();
    db.data.chats.push(msg);
    if (db.data.chats.length > 500) db.data.chats = db.data.chats.slice(-500);
    await db.write();
    io.emit('chat-message', msg);
  });

  socket.on('admin:delete-message', async ({ id }, callback) => {
    if (socket.user.role !== 'admin') return callback?.({ error: 'Akses ditolak' });
    await db.read();
    const idx = db.data.chats.findIndex(c => c.id === id);
    if (idx === -1) return callback?.({ error: 'Pesan tidak ditemukan' });
    db.data.chats.splice(idx, 1);
    await db.write();
    io.emit('chat-deleted', { id });
    callback?.({ success: true });
  });

  socket.on('disconnect', () => {
    io.emit('online-count', io.engine.clientsCount);
  });
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`💬  ChatRm`);
  console.log(`🌐 http://0.0.0.0:${PORT}`);
});