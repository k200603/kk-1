const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'phone_inventory_secret_key_2024';
const ADMIN_KEY = process.env.ADMIN_KEY || 'admin888';

// ===== 中间件 =====
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ===== 数据存储 =====
const DATA_DIR = path.join(__dirname, 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

function readJSON(file, fallback) {
  const fp = path.join(DATA_DIR, file);
  if (!fs.existsSync(fp)) return fallback;
  try { return JSON.parse(fs.readFileSync(fp, 'utf8')); } catch(e) { return fallback; }
}
function writeJSON(file, data) {
  fs.writeFileSync(path.join(DATA_DIR, file), JSON.stringify(data, null, 2), 'utf8');
}

function getUsers() { return readJSON('users.json', []); }
function saveUsers(u) { writeJSON('users.json', u); }
function getPhones(uid) { return readJSON(`phones_${uid}.json`, []); }
function savePhones(uid, p) { writeJSON(`phones_${uid}.json`, p); }
function getNextId(uid) { return readJSON(`nextid_${uid}.json`, 1); }
function saveNextId(uid, n) { writeJSON(`nextid_${uid}.json`, n); }
function getLogs() { return readJSON('logs.json', []); }
function saveLogs(l) { writeJSON('logs.json', l); }

function addLog(type, detail, userId, userName) {
  const logs = getLogs();
  logs.unshift({ id: Date.now(), type, detail, userId: userId||null, userName: userName||null, time: new Date().toISOString() });
  if (logs.length > 1000) logs.length = 1000;
  saveLogs(logs);
}

// 初始化默认管理员
(function initAdmin() {
  const users = getUsers();
  if (!users.find(u => u.role === 'admin')) {
    const hash = bcrypt.hashSync('admin888', 10);
    users.push({
      id: 'u_admin', username: 'admin', displayName: '系统管理员', password: hash,
      role: 'admin', disabled: false, createTime: new Date().toISOString()
    });
    saveUsers(users);
    savePhones('u_admin', []);
    saveNextId('u_admin', 1);
    console.log('✅ 默认管理员已创建: admin / admin888');
  }
})();

// ===== JWT 认证中间件 =====
function auth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: '未登录' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const users = getUsers();
    const user = users.find(u => u.id === decoded.id);
    if (!user || user.disabled) return res.status(401).json({ error: '账号无效或已禁用' });
    req.user = user;
    next();
  } catch(e) { return res.status(401).json({ error: '登录已过期' }); }
}

function adminOnly(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ error: '需要管理员权限' });
  next();
}

// ===== 认证路由 =====
app.post('/api/register', (req, res) => {
  const { username, displayName, password, role, adminKey } = req.body;
  if (!username || username.length < 3 || !/^[a-zA-Z0-9_]+$/.test(username))
    return res.status(400).json({ error: '用户名需3-20位字母数字下划线' });
  if (!displayName) return res.status(400).json({ error: '请输入显示名称' });
  if (!password || password.length < 6) return res.status(400).json({ error: '密码至少6位' });
  if (role === 'admin' && adminKey !== ADMIN_KEY) return res.status(400).json({ error: '管理员口令错误' });

  const users = getUsers();
  if (users.find(u => u.username === username)) return res.status(400).json({ error: '用户名已存在' });

  const hash = bcrypt.hashSync(password, 10);
  const newUser = {
    id: 'u_' + Date.now(), username, displayName, password: hash,
    role: role || 'user', disabled: false, createTime: new Date().toISOString()
  };
  users.push(newUser);
  saveUsers(users);
  savePhones(newUser.id, []);
  saveNextId(newUser.id, 1);
  addLog('注册', `新用户注册: ${displayName} (${newUser.role})`, newUser.id, displayName);

  const token = jwt.sign({ id: newUser.id }, JWT_SECRET, { expiresIn: '7d' });
  const { password: _, ...safe } = newUser;
  res.json({ token, user: safe });
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: '请输入用户名和密码' });

  const users = getUsers();
  const user = users.find(u => u.username === username);
  if (!user) return res.status(400).json({ error: '用户名不存在' });
  if (user.disabled) return res.status(400).json({ error: '账号已被禁用' });
  if (!bcrypt.compareSync(password, user.password)) return res.status(400).json({ error: '密码错误' });

  addLog('登录', '用户登录', user.id, user.displayName);
  const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: '7d' });
  const { password: _, ...safe } = user;
  res.json({ token, user: safe });
});

app.put('/api/password', auth, (req, res) => {
  const { oldPassword, newPassword } = req.body;
  if (!bcrypt.compareSync(oldPassword, req.user.password)) return res.status(400).json({ error: '当前密码错误' });
  if (!newPassword || newPassword.length < 6) return res.status(400).json({ error: '新密码至少6位' });
  const users = getUsers();
  const u = users.find(x => x.id === req.user.id);
  u.password = bcrypt.hashSync(newPassword, 10);
  saveUsers(users);
  addLog('管理', '修改密码', req.user.id, req.user.displayName);
  res.json({ message: '密码修改成功' });
});

// ===== 手机 CRUD =====
app.get('/api/phones', auth, (req, res) => {
  const phones = getPhones(req.user.id);
  res.json(phones);
});

app.post('/api/phones', auth, (req, res) => {
  const { brand, model, imei, storage, condition, color, purchasePrice, purchaseDate, source, accessory, remark } = req.body;
  if (!brand || !model) return res.status(400).json({ error: '品牌和型号不能为空' });
  if (purchasePrice == null || purchasePrice < 0) return res.status(400).json({ error: '请输入有效的收购价' });
  if (!purchaseDate) return res.status(400).json({ error: '请选择收购日期' });

  const phones = getPhones(req.user.id);
  let nextId = getNextId(req.user.id);
  const phone = {
    id: nextId, brand, model, imei: imei||'', storage: storage||'', condition: condition||'',
    color: color||'', purchasePrice: parseFloat(purchasePrice), purchaseDate, source: source||'',
    accessory: accessory||'', remark: remark||'', status: 'instock',
    createDate: new Date().toISOString(), owner: req.user.id
  };
  phones.push(phone);
  savePhones(req.user.id, phones);
  saveNextId(req.user.id, nextId + 1);
  addLog('入库', `${brand} ${model} 入库，收购价 ¥${purchasePrice}`, req.user.id, req.user.displayName);
  res.json(phone);
});

app.put('/api/phones/:id/sell', auth, (req, res) => {
  const phoneId = parseInt(req.params.id);
  const { salePrice, saleDate, buyer, outType, saleRemark } = req.body;
  if (salePrice == null || salePrice < 0) return res.status(400).json({ error: '请输入有效的售价' });
  if (!saleDate) return res.status(400).json({ error: '请选择出库日期' });

  const phones = getPhones(req.user.id);
  const phone = phones.find(p => p.id === phoneId);
  if (!phone) return res.status(404).json({ error: '手机不存在' });
  if (phone.status !== 'instock') return res.status(400).json({ error: '该手机已不在库' });

  const profit = outType === '已售' ? (parseFloat(salePrice) - phone.purchasePrice) : 0;
  phone.status = outType === '退货' ? 'returned' : 'sold';
  phone.salePrice = parseFloat(salePrice);
  phone.saleDate = saleDate;
  phone.buyer = buyer || '';
  phone.outType = outType || '已售';
  phone.saleRemark = saleRemark || '';
  phone.profit = profit;
  phone.saleCreateDate = new Date().toISOString();

  savePhones(req.user.id, phones);
  addLog('出库', `${phone.brand} ${phone.model} ${phone.outType}，售价 ¥${salePrice}，利润 ¥${profit.toFixed(2)}`, req.user.id, req.user.displayName);
  res.json(phone);
});

app.delete('/api/phones/:id', auth, (req, res) => {
  const phoneId = parseInt(req.params.id);
  const phones = getPhones(req.user.id);
  const phone = phones.find(p => p.id === phoneId);
  if (!phone) return res.status(404).json({ error: '手机不存在' });
  addLog('管理', `删除手机 ${phone.brand} ${phone.model}`, req.user.id, req.user.displayName);
  savePhones(req.user.id, phones.filter(p => p.id !== phoneId));
  res.json({ message: '已删除' });
});

// ===== 管理员路由 =====
app.get('/api/admin/users', auth, adminOnly, (req, res) => {
  const users = getUsers().map(u => { const { password, ...safe } = u; return safe; });
  res.json(users);
});

app.post('/api/admin/users', auth, adminOnly, (req, res) => {
  const { username, displayName, password, role } = req.body;
  if (!username || username.length < 3 || !/^[a-zA-Z0-9_]+$/.test(username))
    return res.status(400).json({ error: '用户名需3-20位字母数字下划线' });
  if (!displayName) return res.status(400).json({ error: '请输入显示名称' });
  if (!password || password.length < 6) return res.status(400).json({ error: '密码至少6位' });

  const users = getUsers();
  if (users.find(u => u.username === username)) return res.status(400).json({ error: '用户名已存在' });

  const hash = bcrypt.hashSync(password, 10);
  const newUser = {
    id: 'u_' + Date.now(), username, displayName, password: hash,
    role: role || 'user', disabled: false, createTime: new Date().toISOString()
  };
  users.push(newUser);
  saveUsers(users);
  savePhones(newUser.id, []);
  saveNextId(newUser.id, 1);
  addLog('管理', `管理员创建用户: ${displayName} (${newUser.role})`, req.user.id, req.user.displayName);
  const { password: _, ...safe } = newUser;
  res.json(safe);
});

app.put('/api/admin/users/:id/toggle', auth, adminOnly, (req, res) => {
  const users = getUsers();
  const u = users.find(x => x.id === req.params.id);
  if (!u) return res.status(404).json({ error: '用户不存在' });
  if (u.id === req.user.id) return res.status(400).json({ error: '不能禁用自己' });
  u.disabled = !u.disabled;
  saveUsers(users);
  addLog('管理', `${u.disabled?'禁用':'启用'}用户 ${u.displayName}`, req.user.id, req.user.displayName);
  const { password, ...safe } = u;
  res.json(safe);
});

app.delete('/api/admin/users/:id', auth, adminOnly, (req, res) => {
  const users = getUsers();
  const u = users.find(x => x.id === req.params.id);
  if (!u) return res.status(404).json({ error: '用户不存在' });
  if (u.id === req.user.id) return res.status(400).json({ error: '不能删除自己' });
  saveUsers(users.filter(x => x.id !== u.id));
  addLog('管理', `删除用户 ${u.displayName}`, req.user.id, req.user.displayName);
  res.json({ message: '已删除' });
});

app.get('/api/admin/all-phones', auth, adminOnly, (req, res) => {
  const users = getUsers();
  let all = [];
  users.forEach(u => {
    const phones = getPhones(u.id);
    phones.forEach(p => { p._owner = u.displayName; p._ownerId = u.id; });
    all = all.concat(phones);
  });
  res.json(all);
});

app.get('/api/admin/logs', auth, adminOnly, (req, res) => {
  res.json(getLogs());
});

app.delete('/api/admin/logs', auth, adminOnly, (req, res) => {
  saveLogs([]);
  addLog('管理', '清空操作日志', req.user.id, req.user.displayName);
  res.json({ message: '日志已清空' });
});

// SPA fallback
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ===== 启动 =====
app.listen(PORT, () => {
  console.log(`\n🚀 二手手机库存管理系统已启动！`);
  console.log(`   本地访问: http://localhost:${PORT}`);
  console.log(`   默认管理员: admin / admin888\n`);
});
