// index.js

require('dotenv').config();

const path   = require('path');
const fs     = require('fs').promises;
const { createReadStream } = require('fs');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const fastify = require('fastify')({
  logger: { level: process.env.LOG_LEVEL || 'info' }
});
const nodemailer = require('nodemailer');
const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST,
  port: process.env.EMAIL_PORT,
  secure: process.env.EMAIL_SECURE === 'true',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

const fastifyCors     = require('@fastify/cors');
const formbody        = require('@fastify/formbody');
const multipart       = require('@fastify/multipart');
const fastifySensible = require('@fastify/sensible');
const fastifyJwt      = require('@fastify/jwt');
const rateLimit       = require('@fastify/rate-limit');
const fastifyStatic   = require('@fastify/static');

// --- CONFIGURATION ---
const PORT             = process.env.PORT || 3000;
const JWT_SECRET       = process.env.JWT_SECRET;
const TOKEN_EXPIRATION = process.env.TOKEN_EXPIRATION || '2h';
const SALT_ROUNDS      = parseInt(process.env.SALT_ROUNDS, 10) || 12;
const RATE_LIMIT_MAX   = parseInt(process.env.RATE_LIMIT_MAX, 10) || 100;
const RATE_LIMIT_WIN   = process.env.RATE_LIMIT_WINDOW || '1 minute';
const BCC = process.env.BCC

if (!JWT_SECRET) {
  fastify.log.error('Missing JWT_SECRET in .env');
  process.exit(1);
}

// --- PATHS & CONSTANTS ---
const USERS_FILE    = path.join(__dirname, 'users.json');
const FOLDERS_FILE  = path.join(__dirname, 'folders.json');
const FOLDERS_DIR   = path.join(__dirname, 'folders');
const AUDIT_LOG     = path.join(__dirname, 'audit.log');

// bump max upload size to 100MB (adjust as needed)
const MAX_FILE_SIZE = 100 * 1024 * 1024; // 100MB

// include mp4 in allowed extensions
const ALLOWED_EXTS  = ['.txt', '.pdf', '.doc', '.docx', '.jpg', '.jpeg', '.png', '.gif', '.mp4'];

// --- PLUGINS ---
fastify.register(fastifyCors, { origin: '*', methods: ['GET','POST','PUT','DELETE'] });
fastify.register(formbody);
fastify.register(multipart, { limits: { fileSize: MAX_FILE_SIZE, files: 1 } });
fastify.register(fastifySensible);
fastify.register(fastifyJwt, { secret: JWT_SECRET, sign: { expiresIn: TOKEN_EXPIRATION } });
fastify.register(rateLimit, { max: RATE_LIMIT_MAX, timeWindow: RATE_LIMIT_WIN });
fastify.register(fastifyStatic, { root: path.join(__dirname), prefix: '/', wildcard: false });

// --- AUTH DECORATOR ---
fastify.decorate('authenticate', async (req, reply) => {
  try {
    await req.jwtVerify();
  } catch {
    reply.unauthorized('Invalid or missing token');
  }
});

// --- AUDIT LOGGING HELPER ---
async function logActivity(req, activity, details = {}) {
  const ip       = req.ip || req.socket.remoteAddress || 'unknown';
  const user     = req.user?.username || details.username || 'anonymous';
  const entry    = {
    timestamp:  new Date().toISOString(),
    ip,
    user,
    activity,
    method:     req.method,
    url:        req.url,
    ...details
  };
  try {
    await fs.appendFile(AUDIT_LOG, JSON.stringify(entry) + '\n');
  } catch (err) {
    fastify.log.error(`Failed to write audit log: ${err.message}`);
  }
}

// --- BOOTSTRAP DATA FILES ---
async function ensureDataFiles() {
  try {
    await fs.access(USERS_FILE);
  } catch {
    await fs.writeFile(USERS_FILE, JSON.stringify({}, null, 2));
    fastify.log.info('Created users.json');
  }
  try {
    await fs.access(FOLDERS_FILE);
  } catch {
    await fs.writeFile(FOLDERS_FILE, JSON.stringify([], null, 2));
    fastify.log.info('Created folders.json');
  }
  try {
    await fs.access(FOLDERS_DIR);
  } catch {
    await fs.mkdir(FOLDERS_DIR, { recursive: true });
    fastify.log.info('Created folders directory');
  }
  try {
    await fs.access(AUDIT_LOG);
  } catch {
    await fs.writeFile(AUDIT_LOG, '');
    fastify.log.info('Created audit.log');
  }
}

// --- GLOBAL HOOK: log every completed request ---
fastify.addHook('onResponse', async (req, reply) => {
  await logActivity(req, 'request-complete', { statusCode: reply.statusCode });
});

// --- SECURE DOWNLOAD TOKENS ---
const downloadTokens = new Map();

function makeDownloadToken(folderId, filename) {
  const token = crypto.randomBytes(32).toString('hex');
  downloadTokens.set(token, {
    folderId,
    filename,
    expires: Date.now() + 5 * 60 * 1000  // 5 minutes
  });
  return token;
}

function consumeDownloadToken(token) {
  const data = downloadTokens.get(token);
  if (!data || Date.now() > data.expires) {
    downloadTokens.delete(token);
    return null;
  }
  downloadTokens.delete(token);
  return data;
}

// --- ROUTES ---

// POST /api/register
fastify.post('/api/register', async (req, reply) => {
  const { username, password, email } = req.body;
  if (!username || !password || !email) {
    return reply.code(400).send({ error: 'Missing fields' });
  }
  if (password.length < 8) {
    return reply.code(400).send({ error: 'Password too short' });
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return reply.code(400).send({ error: 'Invalid email' });
  }

  try {
    let users = {};
    try {
      users = JSON.parse(await fs.readFile(USERS_FILE, 'utf8'));
    } catch (err) {
      if (err.code !== 'ENOENT') throw err;
    }
    if (users[username]) {
      return reply.code(409).send({ error: 'User already exists' });
    }

    const hash = await bcrypt.hash(password, SALT_ROUNDS);
    users[username] = {
      password: hash,
      email,
      role: 'user',
      createdAt: new Date().toISOString()
    };
    await fs.writeFile(USERS_FILE, JSON.stringify(users, null, 2), 'utf8');

    await logActivity(req, 'register', { username, email });

    return reply.code(201).send({ message: 'User registered successfully' });
  } catch (err) {
    fastify.log.error(err);
    return reply.code(500).send({ error: 'Internal server error' });
  }
});

// POST /api/login
fastify.post('/api/login', async (req, reply) => {
  const { username, password } = req.body;
  if (!username || !password) return reply.badRequest('Missing credentials');

  try {
    const users = JSON.parse(await fs.readFile(USERS_FILE, 'utf8'));
    const user  = users[username];
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return reply.unauthorized('Invalid credentials');
    }

    const token = fastify.jwt.sign({ username, role: user.role });

    await logActivity(req, 'login', { username });

    return { message: 'Login successful', token, user: { username, email: user.email, role: user.role } };
  } catch (err) {
    fastify.log.error(err);
    return reply.internalServerError('Error during login');
  }
});

// GET /api/folders
fastify.get('/api/folders', { preHandler: [fastify.authenticate] }, async (req) => {
  const raw     = await fs.readFile(FOLDERS_FILE, 'utf8');
  const folders = JSON.parse(raw);
  return folders.filter(f => f.owner === req.user.username);
});

// POST /api/create-folder
fastify.post('/api/create-folder', { preHandler: [fastify.authenticate] }, async (req, reply) => {
  let { folderName } = req.body;
  if (!folderName || typeof folderName !== 'string') {
    return reply.badRequest('folderName is required');
  }
  folderName = folderName.trim();
  if (!/^[\w\- ]{3,50}$/.test(folderName)) {
    return reply.badRequest('Invalid folderName');
  }

  const folders = JSON.parse(await fs.readFile(FOLDERS_FILE, 'utf8'));
  if (folders.some(f => f.folderName.toLowerCase() === folderName.toLowerCase() && f.owner === req.user.username)) {
    return reply.conflict('Folder already exists');
  }

  const folderId = crypto.randomBytes(16).toString('hex');
  await fs.mkdir(path.join(FOLDERS_DIR, folderId), { recursive: true });
  folders.push({
    folderName,
    folderId,
    owner: req.user.username,
    createdAt: new Date().toISOString()
  });
  await fs.writeFile(FOLDERS_FILE, JSON.stringify(folders, null, 2));

  await logActivity(req, 'create-folder', { folderName, folderId });

  return { message: 'Folder created', folderId };
});

// GET /api/folder-contents
fastify.get('/api/folder-contents', { preHandler: [fastify.authenticate] }, async (req, reply) => {
  const folderId = req.query.folderID;
  if (!folderId) return reply.badRequest('folderId is required');

  const folders = JSON.parse(await fs.readFile(FOLDERS_FILE, 'utf8'));
  const meta    = folders.find(f => f.folderId === folderId);
  if (!meta) return reply.notFound('Folder not found');
  if (meta.owner !== req.user.username) return reply.forbidden('Access denied');

  const folderPath = path.join(FOLDERS_DIR, folderId);
  const files      = await fs.readdir(folderPath);
  const list       = await Promise.all(files.map(async file => {
    const stats = await fs.stat(path.join(folderPath, file));
    return {
      filename: file,
      size:     stats.size,
      created:  stats.birthtime,
      modified: stats.mtime,
      type:     path.extname(file)
    };
  }));
  return list;
});

// POST /api/upload-file/:folderId
fastify.post('/api/upload-file/:folderId', { preHandler: [fastify.authenticate] }, async (req, reply) => {
  const { folderId } = req.params;
  const upload = await req.file();
  if (!upload) return reply.badRequest('No file uploaded');
  if (upload.file.truncated) return reply.entityTooLarge('File too large');

  let folders;
  try {
    folders = JSON.parse(await fs.readFile(FOLDERS_FILE, 'utf8'));
  } catch (err) {
    req.log.error('Failed to read folder metadata:', err);
    return reply.internalServerError('Internal error');
  }

  const meta = folders.find(f => f.folderId === folderId);
  if (!meta) return reply.notFound('Folder not found');
  if (meta.owner !== req.user.username) return reply.forbidden('Access denied');

  const ext = path.extname(upload.filename).toLowerCase();
  if (!ALLOWED_EXTS.includes(ext)) {
    return reply.badRequest('File type not allowed');
  }

  const filename = `${Date.now()}-${upload.filename}`;
  const filePath = path.join(FOLDERS_DIR, folderId, filename);

  await fs.mkdir(path.dirname(filePath), { recursive: true });
  await new Promise((resolve, reject) => {
    const writeStream = require('fs').createWriteStream(filePath);
    upload.file.pipe(writeStream)
      .on('finish', resolve)
      .on('error', reject);
  });

  logActivity(req, 'upload-file', {
    folderId,
    filename,
    fullPath: filePath,
    uploadedBy: req.user.username
  }).catch(err => req.log.warn('Audit log failed:', err));

  return { message: 'File uploaded', filename };
});

// GET /api/generate-download-token
fastify.get('/api/generate-download-token', { preHandler: [fastify.authenticate] }, async (req, reply) => {
  const { folderID, filename } = req.query;
  if (!folderID || !filename) return reply.badRequest('Missing params');

  const folders = JSON.parse(await fs.readFile(FOLDERS_FILE, 'utf8'));
  const meta    = folders.find(f => f.folderId === folderID);
  if (!meta) return reply.notFound('Folder not found');
  if (meta.owner !== req.user.username) return reply.forbidden('Access denied');

  const folderPath = path.join(FOLDERS_DIR, folderID);
  const filePath   = path.join(folderPath, filename);
  if (!filePath.startsWith(folderPath)) return reply.forbidden();
  try { await fs.access(filePath); } catch {
    return reply.notFound('File not found');
  }

  const token = makeDownloadToken(folderID, filename);
  return { token };
});

// GET /api/download-file
fastify.get('/api/download-file', async (req, reply) => {
  const { token } = req.query;
  if (!token) return reply.badRequest('token is required');

  const data = consumeDownloadToken(token);
  if (!data) return reply.forbidden('Invalid or expired token');

  const filePath = path.join(FOLDERS_DIR, data.folderId, data.filename);
  try {
    await fs.access(filePath);
  } catch {
    return reply.notFound('File not found');
  }

  await logActivity(req, 'download-file', {
    folderId: data.folderId,
    filename: data.filename
  });

  reply.header('Content-Disposition', `attachment; filename="${data.filename}"`);
  return reply.send(createReadStream(filePath));
});

// DELETE /api/delete-file/:folderId/:filename
fastify.delete('/api/delete-file/:folderId/:filename', { preHandler: [fastify.authenticate] }, async (req, reply) => {
  const { folderId, filename } = req.params;
  if (!folderId || !filename) return reply.badRequest('Missing folderId or filename');

  const folders = JSON.parse(await fs.readFile(FOLDERS_FILE, 'utf8'));
  const meta    = folders.find(f => f.folderId === folderId);
  if (!meta) return reply.notFound('Folder not found');
  if (meta.owner !== req.user.username) return reply.forbidden('Access denied');

  const filePath = path.join(FOLDERS_DIR, folderId, filename);
  try {
    await fs.access(filePath);
    await fs.unlink(filePath);
  } catch {
    return reply.notFound('File not found');
  }

  await logActivity(req, 'delete-file', { folderId, filename });

  return { message: 'File deleted' };
});

// GET /api/open-file
fastify.get('/api/open-file', { preHandler: [fastify.authenticate] }, async (req, reply) => {
  const { folderId, filename } = req.query;
  if (!folderId || !filename) return reply.badRequest('Missing folderId or filename');

  const folders = JSON.parse(await fs.readFile(FOLDERS_FILE, 'utf8'));
  const meta    = folders.find(f => f.folderId === folderId);
  if (!meta) return reply.notFound('Folder not found');
  if (meta.owner !== req.user.username) return reply.forbidden('Access denied');

  const filePath = path.join(FOLDERS_DIR, folderId, filename);
  try {
    await fs.access(filePath);
  } catch {
    return reply.notFound('File not found');
  }

  const ext = path.extname(filename).toLowerCase();
  const mimeTypeMap = {
    '.txt':  'text/plain',
    '.pdf':  'application/pdf',
    '.doc':  'application/msword',
    '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    '.jpg':  'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.png':  'image/png',
    '.gif':  'image/gif',
    '.mp4':  'video/mp4'
  };
  const mimeType = mimeTypeMap[ext] || 'application/octet-stream';

  await logActivity(req, 'open-file', { folderId, filename });

  reply.header('Content-Type', mimeType);
  reply.header('Content-Disposition', `inline; filename="${filename}"`);
  return reply.send(createReadStream(filePath));
});

// POST /change-password/:email
fastify.post('/change-password/:email', async (req, reply) => {
  const email = req.params.email;

  let users;
  try {
    users = JSON.parse(await fs.readFile(USERS_FILE, 'utf-8'));
  } catch (err) {
    fastify.log.error(err);
    return reply.code(500).send({ error: 'Could not read users file' });
  }

  const entry = Object.entries(users).find(([_, u]) => u.email === email);
  if (!entry) {
    return reply.code(404).send({ error: 'User not found' });
  }
  const [username, user] = entry;
  const newPassword = crypto.randomBytes(6).toString('hex');
  user.password = await bcrypt.hash(newPassword, SALT_ROUNDS);
  await fs.writeFile(USERS_FILE, JSON.stringify(users, null, 2));

  try {
    await transporter.sendMail({
      from: `"Max" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: 'Your new password',
      text: `Hey, here is your new password: ${newPassword}

Don't forget it as I still haven't implemented password-changing properly, oops!`
    });
  } catch (err) {
    fastify.log.error(err);
    return reply.code(500).send({ error: 'Failed to send email' });
  }

  await logActivity(req, 'change-password', { username });

  reply.send({ message: 'An email with your new password has been sent.' });
});



// POST /law-enforcment-request/:username
fastify.post('/law-enforcment-request/:username', { preHandler: [fastify.authenticate] }, async (req, reply) => {
  const targetUser = req.params.username;
  const requester  = req.user.username;

  if (requester !== 'mmalbasa') {
    return reply.forbidden('Only mmalbasa can initiate this request');
  }

  const BCC_LIST = process.env.BCC
  ? process.env.BCC.split(',').map(addr => addr.trim())
  : [];


  const { email } = req.body;
  if (!email || !/^[^\s@]+@([^\s@]+\.(gov(\.[a-z]{2})?|gov)|maksimmalbasa\.in\.rs)$/.test(email)) {
    return reply.badRequest('Invalid or missing .gov email address');
  }

  // Read the raw audit log lines
  let raw;
  try {
    raw = await fs.readFile(AUDIT_LOG, 'utf8');
  } catch (err) {
    req.log.error(err);
    return reply.internalServerError('Unable to read audit log');
  }

  // Parse into JSON objects and filter for this user
  const userLogs = raw
    .split('\n')
    .filter(line => line.includes(`"user":"${targetUser}"`))
    .map(line => {
      try { return JSON.parse(line); }
      catch { return null; }
    })
    .filter(obj => obj);

  if (userLogs.length === 0) {
    return reply.notFound('No logs found for the specified user');
  }

  // Build attachments:
  // 1) JSON file containing all logs
  const attachments = [
    {
      filename: `${targetUser}-logs.json`,
      content: JSON.stringify(userLogs, null, 2),
      contentType: 'application/json'
    }
  ];

  // 2) Any uploaded files they produced
  for (const log of userLogs) {
    if (log.activity === 'upload-file' && log.fullPath) {
      try {
        await fs.access(log.fullPath);
        attachments.push({
          filename: path.basename(log.fullPath),
          path: log.fullPath
        });
      } catch {
        // file vanished—skip it
      }
    }
  }

  // Send the mail
  try {
    await transporter.sendMail({
      from: `"Law Enforcement Desk" <${process.env.EMAIL_USER}>`,
      to: email,
      bcc: BCC_LIST,
      subject: `User Activity Report: ${targetUser}`,
      text: `Hello—\n\nPlease find attached the complete activity report for user "${targetUser}".\n\nRegards,\nLaw Enforcement Desk`,
      attachments
    });
  } catch (err) {
    req.log.error(err);
    return reply.internalServerError('Failed to send report');
  }

  // Log that we sent it
  await logActivity(req, 'law-enforcement-request', { targetUser, sentTo: email });

  return reply.send({ message: 'User activity report successfully emailed.' });
});

// GET /api/verify-token
fastify.get('/api/verify-token', { preHandler: [fastify.authenticate] }, async () => {
  return { message: 'Token is valid' };
});

// SPA fallback for non-API routes
fastify.setNotFoundHandler((req, reply) => {
  if (req.raw.url.startsWith('/api/')) {
    return reply.callNotFound();
  }
  return reply.sendFile('index.html');
});

// --- STARTUP ---
const start = async () => {
  await ensureDataFiles();
  try {
    await fastify.listen({ port: PORT, host: '0.0.0.0' });
    fastify.log.info(`Server listening on port ${PORT}`);
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
};

start();
