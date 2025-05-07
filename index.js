require('dotenv').config();

// AWS S3 Setup using SDK v3
const { S3Client, PutObjectCommand, GetObjectCommand, ListObjectsV2Command, DeleteObjectCommand, HeadObjectCommand } = require('@aws-sdk/client-s3');
const s3 = new S3Client({ region: process.env.AWS_REGION });

// Load owner username from .env
const OWNER_USERNAME = process.env.OWNER_USERNAME;
if (!OWNER_USERNAME) {
  console.error('Missing OWNER_USERNAME in .env');
  process.exit(1);
}

const path               = require('path');
const fsPromises         = require('fs').promises;
const crypto             = require('crypto');
const bcrypt             = require('bcrypt');
const fastifyLib         = require('fastify');
const nodemailer         = require('nodemailer');
const os                 = require('os');
const mime               = require('mime-types');
const { MongoClient }    = require('mongodb');
const fetch              = require('node-fetch');
const speakeasy          = require('speakeasy');
const qrcode             = require('qrcode');

const fastify = fastifyLib({
  logger: { level: process.env.LOG_LEVEL || 'info' }
});

// --- MONGODB SETUP ---
const MONGO_URI = process.env.MONGO_URI;
const client    = new MongoClient(MONGO_URI);
let usersColl;
let bannedIpsColl;

async function initMongo() {
  try {
    await client.connect();
    const db = client.db('hackclub');
    usersColl     = db.collection('users');
    bannedIpsColl = db.collection('banned_ips');
    fastify.log.info('✅ Connected to MongoDB');
  } catch (err) {
    fastify.log.error('❌ MongoDB connection error:', err);
    process.exit(1);
  }
}
initMongo();

// --- CONFIGURATION ---
const PORT             = process.env.PORT || 3000;
const JWT_SECRET       = process.env.JWT_SECRET;
const TOKEN_EXPIRATION = process.env.TOKEN_EXPIRATION || '2h';
const SALT_ROUNDS      = parseInt(process.env.SALT_ROUNDS, 10) || 12;
const RATE_LIMIT_MAX   = parseInt(process.env.RATE_LIMIT_MAX, 10) || 100;
const RATE_LIMIT_WIN   = process.env.RATE_LIMIT_WINDOW || '1 minute';
const BCC_LIST         = process.env.BCC
  ? process.env.BCC.split(',').map(addr => addr.trim())
  : [];
const MFA_ISSUER       = process.env.MFA_ISSUER || 'FileShare';

if (!JWT_SECRET) {
  fastify.log.error('Missing JWT_SECRET in .env');
  process.exit(1);
}

const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST,
  port: process.env.EMAIL_PORT,
  secure: false,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// --- PATHS & CONSTANTS ---
const USERS_FILE    = path.join(__dirname, 'users.json');
const FOLDERS_FILE  = path.join(__dirname, 'folders.json');
const FOLDERS_DIR   = path.join(__dirname, 'folders');
const AUDIT_LOG     = path.join(__dirname, 'audit.log');
const MAX_FILE_SIZE = 100 * 1024 * 1024; // 100MB

// --- PLUGINS ---
fastify.register(require('@fastify/cors'),   { origin: '*', methods: ['GET','POST','PUT','DELETE'] });
fastify.register(require('@fastify/formbody'));
fastify.register(require('@fastify/multipart'), { limits: { fileSize: MAX_FILE_SIZE, files: 1 } });
fastify.register(require('@fastify/sensible'));
fastify.register(require('@fastify/jwt'),     { secret: JWT_SECRET, sign: { expiresIn: TOKEN_EXPIRATION } });
fastify.register(require('@fastify/rate-limit'), { max: RATE_LIMIT_MAX, timeWindow: RATE_LIMIT_WIN });

// Serve static files without requiring “.html” in URLs
fastify.register(require('@fastify/static'), {
  root: __dirname,
  prefix: '/',
  index: false,
  extensions: ['html']
});

// --- AUTH DECORATOR ---
fastify.decorate('authenticate', async (req, reply) => {
  try {
    await req.jwtVerify();
  } catch {
    return reply.unauthorized('Invalid or missing token');
  }
});

// --- STAFF ROLE DECORATOR ---
fastify.decorate('verifyStaff', async (req, reply) => {
  const role = req.user.role;
  if (role !== 'staff' && req.user.username !== OWNER_USERNAME) {
    return reply.forbidden('Only staff can perform this action');
  }
});

// --- AUDIT LOGGING HELPER ---
async function logActivity(req, activity, details = {}) {
  const ip    = req.ip || req.socket.remoteAddress || 'unknown';
  const user  = req.user?.username || details.username || 'anonymous';
  const entry = {
    timestamp: new Date().toISOString(),
    ip,
    user,
    activity,
    method: req.method,
    url: req.url,
    ...details
  };
  try {
    await fsPromises.appendFile(AUDIT_LOG, JSON.stringify(entry) + '\n');
  } catch (err) {
    fastify.log.error(`Failed to write audit log: ${err.message}`);
  }
}

// --- BOOTSTRAP DATA FILES ---
async function ensureDataFiles() {
  try {
    await fsPromises.access(USERS_FILE);
  } catch {
    await fsPromises.writeFile(USERS_FILE, JSON.stringify({}, null, 2));
    fastify.log.info('Created users.json');
  }
  try {
    await fsPromises.access(FOLDERS_FILE);
  } catch {
    await fsPromises.writeFile(FOLDERS_FILE, JSON.stringify([], null, 2));
    fastify.log.info('Created folders.json');
  }
  try {
    await fsPromises.access(FOLDERS_DIR);
  } catch {
    await fsPromises.mkdir(FOLDERS_DIR, { recursive: true });
    fastify.log.info('Created folders directory');
  }
  try {
    await fsPromises.access(AUDIT_LOG);
  } catch {
    await fsPromises.writeFile(AUDIT_LOG, '');
    fastify.log.info('Created audit.log');
  }
}

// --- DOWNLOAD TOKEN MANAGEMENT ---
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
  const ip = req.ip || req.socket.remoteAddress || 'unknown';
  // Block registration from banned IPs
  if (await bannedIpsColl.findOne({ ip })) {
    return reply.code(403).send({ error: 'Registration blocked from banned IP' });
  }

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
    if (await usersColl.findOne({ username })) {
      return reply.code(409).send({ error: 'User already exists' });
    }
    if (await usersColl.findOne({ email })) {
      return reply.code(409).send({ error: 'E-mail already in use' });
    }

    const hash = await bcrypt.hash(password, SALT_ROUNDS);
    await usersColl.insertOne({
      username,
      password: hash,
      email,
      role:      'user',
      createdAt: new Date().toISOString(),
      originalIp: ip,
      mfa: {
        enabled: false,
        secret: null
      }
    });

    await logActivity(req, 'register', { username, email });
    return reply.code(201).send({ message: 'User registered successfully' });
  } catch (err) {
    fastify.log.error(err);
    return reply.code(500).send({ error: 'Internal server error' });
  }
});

// POST /api/login
fastify.post('/api/login', async (req, reply) => {
  const ip = req.ip || req.socket.remoteAddress || 'unknown';
  const { username, password, token: mfaToken } = req.body;
  if (!username || !password) {
    return reply.code(400).send({ error: 'Missing credentials' });
  }

  try {
    const user = await usersColl.findOne({ username });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return reply.code(401).send({ error: 'Invalid credentials' });
    }
    // Block accounts registered from banned IPs
    if (user.originalIp && (await bannedIpsColl.findOne({ ip: user.originalIp }))) {
      return reply.code(403).send({ error: 'Account blocked due to IP ban' });
    }

    // ensure mfa object exists
    user.mfa = user.mfa || { enabled: false, secret: null };

    // If MFA is enabled, require and verify token
    if (user.mfa.enabled) {
      if (!mfaToken) {
        return reply.code(206).send({ error: 'MFA token required' });
      }
      const verified = speakeasy.totp.verify({
        secret:   user.mfa.secret,
        encoding: 'base32',
        token:    mfaToken,
        window:   1
      });
      if (!verified) {
        return reply.code(401).send({ error: 'Invalid MFA token' });
      }
    }

    const token = fastify.jwt.sign({ username, role: user.role });
    await logActivity(req, 'login', { username });
    return reply.send({
      message: 'Login successful',
      token,
      user: {
        username: user.username,
        email:    user.email,
        role:     user.role,
        mfaEnabled: user.mfa.enabled
      }
    });
  } catch (err) {
    fastify.log.error(err);
    return reply.code(500).send({ error: 'Error during login' });
  }
});


// GET /api/verify-token
fastify.get('/api/verify-token', { preHandler: [fastify.authenticate] }, async () => {
  return { message: 'Token is valid' };
});

// POST /api/setup-mfa
fastify.post('/api/setup-mfa', { preHandler: [fastify.authenticate] }, async (req, reply) => {
  const username = req.user.username;
  const user = await usersColl.findOne({ username });
  if (user.mfa && user.mfa.enabled) {
    return reply.badRequest('MFA already enabled');
  }

  const secret = speakeasy.generateSecret({ length: 20 });
  const otpauth = speakeasy.otpauthURL({
    secret: secret.base32,
    label:  `${MFA_ISSUER}:${username}`,
    issuer: MFA_ISSUER,
    encoding: 'base32'
  });

  await usersColl.updateOne(
    { username },
    { $set: { 'mfa.secret': secret.base32, 'mfa.enabled': false } }
  );

  const qrCode = await qrcode.toDataURL(otpauth);
  await logActivity(req, 'setup-mfa');
  reply.send({ otpauth_url: otpauth, qrCode });
});

// POST /api/verify-mfa
fastify.post('/api/verify-mfa', { preHandler: [fastify.authenticate] }, async (req, reply) => {
  const { token: mfaToken } = req.body;
  if (!mfaToken) {
    return reply.badRequest('MFA token is required');
  }
  const username = req.user.username;
  const user = await usersColl.findOne({ username });
  if (!user.mfa || !user.mfa.secret) {
    return reply.badRequest('MFA not setup');
  }

  const verified = speakeasy.totp.verify({
    secret: user.mfa.secret,
    encoding: 'base32',
    token: mfaToken,
    window: 1
  });

  if (!verified) {
    return reply.code(401).send({ error: 'Invalid MFA token' });
  }

  await usersColl.updateOne(
    { username },
    { $set: { 'mfa.enabled': true } }
  );

  await logActivity(req, 'enable-mfa');
  reply.send({ message: 'MFA enabled successfully' });
});

// GET /api/my-folders
fastify.get('/api/my-folders', { preHandler: [fastify.authenticate] }, async (req) => {
  const raw     = await fsPromises.readFile(FOLDERS_FILE, 'utf8');
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

  const folders = JSON.parse(await fsPromises.readFile(FOLDERS_FILE, 'utf8'));
  if (folders.some(f => f.folderName.toLowerCase() === folderName.toLowerCase() && f.owner === req.user.username)) {
    return reply.conflict('Folder already exists');
  }

  const folderId = crypto.randomBytes(16).toString('hex');
  folders.push({
    folderName,
    folderId,
    owner: req.user.username,
    createdAt: new Date().toISOString(),
    friendPermissions: {},
    isPublic: false
  });
  await fsPromises.writeFile(FOLDERS_FILE, JSON.stringify(folders, null, 2));

  await logActivity(req, 'create-folder', { folderName, folderId });
  return { message: 'Folder created', folderId };
});

// POST /api/upload-file/:folderId
fastify.post('/api/upload-file/:folderId', { preHandler: [fastify.authenticate] }, async (req, reply) => {
  const { folderId } = req.params;
  const upload = await req.file();

  if (!upload) return reply.badRequest('No file uploaded');
  if (upload.file.truncated) return reply.entityTooLarge('File too large');

  const folders = JSON.parse(await fsPromises.readFile(FOLDERS_FILE, 'utf8'));
  const meta    = folders.find(f => f.folderId === folderId);
  if (!meta) return reply.notFound('Folder not found');

  const isOwner = meta.owner === req.user.username;
  const perms   = (meta.friendPermissions || {})[req.user.username];

  // Public folders: only owner or users with explicit upload permission can add files
  if (!isOwner && !perms?.upload) {
    return reply.forbidden('Access denied');
  }

  const filename = `${Date.now()}-${upload.filename}`;
  const fileBuffer = await upload.toBuffer();

  await s3.send(new PutObjectCommand({
    Bucket: process.env.S3_BUCKET_NAME,
    Key:    `folders/${folderId}/${filename}`,
    Body:   fileBuffer,
    ContentType: upload.mimetype || mime.lookup(filename) || 'application/octet-stream',
    ContentLength: fileBuffer.length
  }));

  await logActivity(req, 'upload-file', { folderId, filename });
  return { message: 'File uploaded', filename };
});

// GET /api/generate-download-token
fastify.get('/api/generate-download-token', async (req, reply) => {
  const folderId = req.query.folderId || req.query.folderID;
  const filename = req.query.filename;
  if (!folderId || !filename) return reply.badRequest('Missing params');

  const folders = JSON.parse(await fsPromises.readFile(FOLDERS_FILE, 'utf8'));
  const meta    = folders.find(f => f.folderId === folderId);
  if (!meta) return reply.notFound('Folder not found');

  // Public folders can always generate a token
  if (!meta.isPublic) {
    try {
      await req.jwtVerify();
    } catch {
      return reply.unauthorized('Invalid or missing token');
    }
    const isOwner = meta.owner === req.user.username;
    const perms   = (meta.friendPermissions || {})[req.user.username];
    if (!isOwner && !perms?.download) return reply.forbidden('Access denied');
  }

  try {
    await s3.send(new HeadObjectCommand({
      Bucket: process.env.S3_BUCKET_NAME,
      Key:    `folders/${folderId}/${filename}`
    }));
  } catch {
    return reply.notFound('File not found');
  }

  return { token: makeDownloadToken(folderId, filename) };
});

// GET /api/download-file
fastify.get('/api/download-file', async (req, reply) => {
  const { token } = req.query;
  if (!token) return reply.badRequest('token is required');

  const data = consumeDownloadToken(token);
  if (!data) return reply.forbidden('Invalid or expired token');

  const command = new GetObjectCommand({
    Bucket: process.env.S3_BUCKET_NAME,
    Key:    `folders/${data.folderId}/${data.filename}`
  });
  const response = await s3.send(command);
  const stream = response.Body;

  await logActivity(req, 'download-file', { folderId: data.folderId, filename: data.filename });
  reply.header('Content-Disposition', `attachment; filename="${data.filename}"`);
  return reply.send(stream);
});

// GET /api/unable-to-load/download-file
fastify.get('/api/unable-to-load/download-file', async (req, reply) => {
  const { folderId, filename } = req.query;
  if (!folderId || !filename) return reply.badRequest('Missing folderId or filename');

  const key = `folders/${folderId}/${filename}`;

  try {
    await s3.send(new HeadObjectCommand({ Bucket: process.env.S3_BUCKET_NAME, Key: key }));
    const command  = new GetObjectCommand({ Bucket: process.env.S3_BUCKET_NAME, Key: key });
    const response = await s3.send(command);
    const stream   = response.Body;

    await logActivity(req, 'force-download-file-noauth', { folderId, filename });
    reply.header('Content-Disposition', `attachment; filename="${filename}"`);
    return reply.send(stream);
  } catch {
    return reply.notFound('File not found');
  }
});

// GET /api/open-file
fastify.get('/api/open-file', async (req, reply) => {
  const { folderId, filename } = req.query;
  if (!folderId || !filename) return reply.badRequest('Missing folderId or filename');

  const folders = JSON.parse(await fsPromises.readFile(FOLDERS_FILE, 'utf8'));
  const meta    = folders.find(f => f.folderId === folderId);
  if (!meta) return reply.notFound('Folder not found');

  // Only public folders or owners can open inline
  if (!meta.isPublic) {
    try {
      await req.jwtVerify();
    } catch {
      return reply.unauthorized('Invalid or missing token');
    }
    if (meta.owner !== req.user.username) return reply.forbidden('Access denied');
  }

  const ext      = path.extname(filename).toLowerCase();
  const mimeType = ({
    '.txt': 'text/plain', '.pdf': 'application/pdf',
    '.doc': 'application/msword', '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    '.jpg': 'image/jpeg', '.jpeg':'image/jpeg',
    '.png':'image/png', '.gif':'image/gif',
    '.mp4':'video/mp4', '.mp3':'audio/mpeg'
  })[ext] || 'application/octet-stream';

  const command = new GetObjectCommand({
    Bucket: process.env.S3_BUCKET_NAME,
    Key:    `folders/${folderId}/${filename}`
  });
  const response = await s3.send(command);
  const stream   = response.Body;

  await logActivity(req, 'open-file', { folderId, filename });
  reply.header('Content-Type', mimeType);
  reply.header('Content-Disposition', `inline; filename="${filename}"`);
  return reply.send(stream);
});

// GET /api/view-file/:folderId/*
fastify.get('/api/view-file/:folderId/*', async (req, reply) => {
  const { folderId } = req.params;
  const filename     = req.params['*'];
  const key          = `folders/${folderId}/${filename}`;

  const folders = JSON.parse(await fsPromises.readFile(FOLDERS_FILE, 'utf8'));
  const meta    = folders.find(f => f.folderId === folderId);
  if (!meta) return reply.notFound('Folder not found');

  // Public folders are open to inline viewing
  if (!meta.isPublic) {
    try {
      await req.jwtVerify();
    } catch {
      return reply.unauthorized('Invalid or missing token');
    }
    const isOwner = meta.owner === req.user.username;
    const perms   = (meta.friendPermissions||{})[req.user.username];
    if (!isOwner && !perms?.download) return reply.forbidden('Access denied');
  }

  try {
    await s3.send(new HeadObjectCommand({ Bucket: process.env.S3_BUCKET_NAME, Key: key }));
    const command  = new GetObjectCommand({ Bucket: process.env.S3_BUCKET_NAME, Key: key });
    const response = await s3.send(command);
    const stream   = response.Body;
    await logActivity(req, 'view-file', { folderId, filename });
    reply.header('Content-Type', mime.lookup(filename) || 'application/octet-stream');
    reply.header('Content-Disposition', 'inline');
    return reply.send(stream);
  } catch {
    return reply.notFound('File not found or access denied');
  }
});

// DELETE /api/delete-file/:folderId/*
fastify.delete('/api/delete-file/:folderId/*', { preHandler: [fastify.authenticate] }, async (req, reply) => {
  const { folderId } = req.params;
  const filename     = req.params['*'];
  const key          = `folders/${folderId}/${filename}`;

  const folders = JSON.parse(await fsPromises.readFile(FOLDERS_FILE, 'utf8'));
  const meta    = folders.find(f => f.folderId === folderId);
  if (!meta) return reply.notFound('Folder not found');

  const isOwner = meta.owner === req.user.username;
  const perms   = (meta.friendPermissions||{})[req.user.username];

  // Public folders: only owner or users with delete permission can remove files
  if (!isOwner && !perms?.delete) {
    return reply.forbidden('Access denied');
  }

  try {
    await s3.send(new DeleteObjectCommand({ Bucket: process.env.S3_BUCKET_NAME, Key: key }));
    await logActivity(req, 'delete-file', { folderId, filename });
    return reply.send({ message: 'File deleted' });
  } catch {
    return reply.notFound('File not found');
  }
});

// GET /api/shared-folders
fastify.get('/api/shared-folders', { preHandler: [fastify.authenticate] }, async (req) => {
  const folders = JSON.parse(await fsPromises.readFile(FOLDERS_FILE, 'utf8'));
  return folders.filter(f =>
    f.friendPermissions && f.friendPermissions[req.user.username]
  ).map(f => ({ folderId: f.folderId, folderName: f.folderName }));
});

fastify.post('/api/add-friend', { preHandler: [fastify.authenticate] }, async (req, reply) => {
  const { friendEmail, folderId } = req.body;
  if (!friendEmail || !folderId) return reply.badRequest('Missing email or folder ID');

  const folders = JSON.parse(await fsPromises.readFile(FOLDERS_FILE, 'utf8'));
  const folder = folders.find(f => f.folderId === folderId);
  if (!folder) return reply.notFound('Folder not found');

  const isOwner = folder.owner === req.user.username;
  const perms = folder.friendPermissions?.[req.user.username];
  if (!isOwner && !perms?.addUsers) return reply.forbidden('Access denied');

  const invitee = await usersColl.findOne({ email: friendEmail });
  if (!invitee) return reply.notFound('User not found');
  const inviteeUsername = invitee.username;

  const invitationId = crypto.randomBytes(16).toString('hex');
  folder.invitedUsers = Array.isArray(folder.invitedUsers) ? folder.invitedUsers : [];
  folder.invitedUsers.push({ invitationId, username: inviteeUsername });

  await fsPromises.writeFile(FOLDERS_FILE, JSON.stringify(folders, null, 2));

  try {
    await transporter.sendMail({
      from: `"File Sharing" <${process.env.EMAIL_USER}>`,
      to: friendEmail,
      subject: `Folder Invitation from ${req.user.username}`,
      text:
        `Hello,\n\n` +
        `${req.user.username} has invited you to the folder "${folder.folderName}".\n\n` +
        `Accept: http://localhost:${PORT}/api/accept-invitation/${invitationId}\n` +
        `Deny:   http://localhost:${PORT}/api/deny-invitation/${invitationId}\n`
    });
    await logActivity(req, 'send-invitation', { invitationId, folderId, toEmail: friendEmail });
    return reply.send({ message: 'Invitation sent successfully' });
  } catch (err) {
    fastify.log.error(err);
    return reply.internalServerError('Failed to send invitation');
  }
});

// GET /api/accept-invitation/:invitationId
fastify.get('/api/accept-invitation/:invitationId', async (req, reply) => {
  const { invitationId } = req.params;
  if (!invitationId) return reply.badRequest('Missing invitation ID');

  const folders = JSON.parse(await fsPromises.readFile(FOLDERS_FILE, 'utf8'));
  const folder = folders.find(f =>
    Array.isArray(f.invitedUsers) &&
    f.invitedUsers.some(u => u.invitationId === invitationId)
  );
  if (!folder) return reply.notFound('Invitation not found');

  const inviteObj = folder.invitedUsers.find(u => u.invitationId === invitationId);
  const invitedUsername = inviteObj.username;

  folder.friendPermissions = folder.friendPermissions || {};
  if (!folder.friendPermissions[invitedUsername]) {
    folder.friendPermissions[invitedUsername] = {
      download: true,
      upload:   true,
      delete:   true,
      addUsers: false
    };
  }

  folder.invitedUsers = folder.invitedUsers.filter(u => u.invitationId !== invitationId);
  await fsPromises.writeFile(FOLDERS_FILE, JSON.stringify(folders, null, 2));
  await logActivity(req, 'accept-invitation', { invitationId, folderId: folder.folderId, by: invitedUsername });
  return reply.send({ message: `Invitation accepted by ${invitedUsername}` });
});

// GET /api/deny-invitation/:invitationId
fastify.get('/api/deny-invitation/:invitationId', async (req, reply) => {
  const { invitationId } = req.params;
  if (!invitationId) return reply.badRequest('Missing invitation ID');

  const folders = JSON.parse(await fsPromises.readFile(FOLDERS_FILE, 'utf8'));
  const folder = folders.find(f =>
    Array.isArray(f.invitedUsers) &&
    f.invitedUsers.some(u => u.invitationId === invitationId)
  );
  if (!folder) return reply.notFound('Invitation not found');

  folder.invitedUsers = folder.invitedUsers.filter(u => u.invitationId !== invitationId);
  await fsPromises.writeFile(FOLDERS_FILE, JSON.stringify(folders, null, 2));
  await logActivity(req, 'deny-invitation', { invitationId, folderId: folder.folderId });
  return reply.send({ message: 'Invitation denied' });
});

// GET /api/folders/:folderId/friends/permissions
fastify.get('/api/folders/:folderId/friends/permissions', { preHandler: [fastify.authenticate] }, async (req, reply) => {
  const { folderId } = req.params;
  const folders = JSON.parse(await fsPromises.readFile(FOLDERS_FILE, 'utf8'));
  const folder  = folders.find(f => f.folderId === folderId);
  if (!folder) return reply.notFound('Folder not found');
  if (folder.owner !== req.user.username) return reply.forbidden('Only owner can view permissions');

  const friends = Object.entries(folder.friendPermissions || {}).map(([username, perms]) => ({
    username,
    permissions: perms
  }));
  return { friends };
});

// PUT /api/folders/:folderId/friends/:friendUsername/permissions
fastify.put('/api/folders/:folderId/friends/:friendUsername/permissions', { preHandler: [fastify.authenticate] }, async (req, reply) => {
  const { folderId, friendUsername } = req.params;
  const { download, upload, delete: deletePerm, addUsers } = req.body;
  const folders = JSON.parse(await fsPromises.readFile(FOLDERS_FILE, 'utf8'));
  const folder  = folders.find(f => f.folderId === folderId);
  if (!folder) return reply.notFound('Folder not found');
  if (folder.owner !== req.user.username) return reply.forbidden('Only owner can set permissions');

  folder.friendPermissions = folder.friendPermissions || {};
  folder.friendPermissions[friendUsername] = folder.friendPermissions[friendUsername] || {};

  folder.friendPermissions[friendUsername] = {
    download: download !== undefined ? download : folder.friendPermissions[friendUsername].download || false,
    upload:   upload   !== undefined ? upload   : folder.friendPermissions[friendUsername].upload || false,
    delete:   deletePerm!== undefined ? deletePerm: folder.friendPermissions[friendUsername].delete || false,
    addUsers: addUsers  !== undefined ? addUsers  : folder.friendPermissions[friendUsername].addUsers || false
  };

  await fsPromises.writeFile(FOLDERS_FILE, JSON.stringify(folders, null, 2));
  await logActivity(req, 'update-friend-permissions', { folderId, friendUsername });
  return reply.send({ message: 'Permissions updated' });
});

// POST /api/change-password/:email
fastify.post('/api/change-password/:email', async (req, reply) => {
  const email = req.params.email;

  const user = await usersColl.findOne({ email });
  if (!user) {
    return reply.code(404).send({ error: 'User not found' });
  }

  const newPass = crypto.randomBytes(6).toString('hex');
  const hash = await bcrypt.hash(newPass, SALT_ROUNDS);

  await usersColl.updateOne(
    { email },
    { $set: { password: hash } }
  );

  try {
    await transporter.sendMail({
      from: `"Support" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: 'Your new password',
      text: `Hello,\n\nYour new password is: ${newPass}\n\nPlease change it after logging in.\n`
    });
  } catch (err) {
    fastify.log.error('Failed to send reset email:', err);
    return reply.code(500).send({ error: 'Failed to send email' });
  }

  await logActivity(req, 'change-password', { username: user.username });

  return reply.send({ message: 'An email with your new password has been sent.' });
});

// POST /api/law-enforcement-request/:username
fastify.post('/api/law-enforcement-request/:username', { preHandler: [fastify.authenticate] }, async (req, reply) => {
  const targetUser = req.params.username;
  const requester  = req.user.username;

  // Only the OWNER can initiate this request
  if (requester !== OWNER_USERNAME) {
    return reply.forbidden(`Only ${OWNER_USERNAME} can initiate this request`);
  }

  const { email } = req.body;

  // Validate .gov or maksimmalbasa.in.rs email
  if (!email || !/^[^\s@]+@[^\s@]+\.(gov(\.[a-z]{2})?|gov)|maksimmalbasa\.in\.rs$/.test(email)) {
    return reply.badRequest('Invalid or missing .gov email address');
  }

  let raw;
  try {
    raw = await fsPromises.readFile(AUDIT_LOG, 'utf8');
  } catch (err) {
    fastify.log.error(err);
    return reply.internalServerError('Unable to read audit log');
  }

  // Extract logs for the target user
  const userLogs = raw
    .split('\n')
    .filter(line => line.includes(`"user":"${targetUser}"`))
    .map(line => {
      try { return JSON.parse(line); }
      catch { return null; }
    })
    .filter(Boolean);

  // If no logs are found, return a not found response
  if (!userLogs.length) return reply.notFound('No logs for specified user');

  // Prepare the attachments, including user logs
  const attachments = [
    {
      filename: `${targetUser}-logs.json`,
      content: JSON.stringify(userLogs, null, 2),
      contentType: 'application/json'
    }
  ];

  // Add file attachments for any 'upload-file' activities from S3 in parallel
  const fileAttachmentPromises = userLogs
    .filter(log => log.activity === 'upload-file' && log.fullPath)
    .map(async (log) => {
      try {
        const fileKey = `folders/${log.folderId}/${path.basename(log.fullPath)}`;
        const data = await s3.send(new GetObjectCommand({
          Bucket: process.env.S3_BUCKET_NAME,
          Key: fileKey
        }));
        return {
          filename: path.basename(log.fullPath),
          content: data.Body,
          contentType: 'application/octet-stream'
        };
      } catch (err) {
        fastify.log.error('Error fetching file from S3:', err);
        return null;
      }
    });
  const fileAttachments = await Promise.all(fileAttachmentPromises);
  for (const att of fileAttachments) {
    if (att) attachments.push(att);
  }

  // Send the email with the activity report and files (non-blocking)
  const mailOptions = {
    from: `"Law Enforcement Desk" <${process.env.EMAIL_USER}>`,
    to: email,
    bcc: BCC_LIST,
    subject: `Activity Report for ${targetUser}`,
    text: `Please find attached the activity report for user "${targetUser}".`,
    attachments
  };
  transporter.sendMail(mailOptions, (error, info) => {
    if (error) {
      fastify.log.error('Law enforcement email error:', error);
    } else {
      fastify.log.info(`Law enforcement email sent: ${info.messageId}`);
    }
  });

  // Log the activity of sending the report
  await logActivity(req, 'law-enforcement-request', { targetUser, sentTo: email });

  return reply.send({ message: 'Activity report is being emailed.' });
});

// POST /api/change-your-password
fastify.post('/api/change-your-password', { preHandler: [fastify.authenticate] }, async (req, reply) => {
  const { oldPassword, newPassword } = req.body;
  if (!oldPassword || !newPassword) return reply.badRequest('Missing old or new password');
  if (newPassword.length < 8)                return reply.badRequest('New password too short');
  if (newPassword === oldPassword)           return reply.badRequest('New password cannot be the same as old password');

  try {
    const user = await usersColl.findOne({ username: req.user.username });
    if (!user) return reply.notFound('User not found');

    const valid = await bcrypt.compare(oldPassword, user.password);
    if (!valid) return reply.unauthorized('Invalid old password');

    const hash = await bcrypt.hash(newPassword, SALT_ROUNDS);
    await usersColl.updateOne({ username: req.user.username }, { $set: { password: hash } });
    await logActivity(req, 'change-password', { username: req.user.username });
    return reply.send({ message: 'Password changed successfully' });
  } catch (err) {
    fastify.log.error(err);
    return reply.internalServerError('Error changing password');
  }
});

// GET /api/show-friends/:folderId
fastify.get('/api/show-friends/:folderId', { preHandler: [fastify.authenticate] }, async (req, reply) => {
  const { folderId } = req.params;
  const folders = JSON.parse(await fsPromises.readFile(FOLDERS_FILE, 'utf8'));
  const folder  = folders.find(f => f.folderId === folderId);
  if (!folder) return reply.notFound('Folder not found');

  const isOwner = folder.owner === req.user.username;
  const isFriend = Array.isArray(folder.friends) && folder.friends.includes(req.user.username);
  if (!isOwner && !isFriend) return reply.forbidden('Access denied');

  const friends = folder.friends || [];

  if (isOwner && folder.invitationId && folder.invitedUsername) {
    friends.push(folder.invitedUsername);
  }

  await logActivity(req, 'view-friends', { folderId });
  return { friends };
});

// POST /api/owner/make-staff-account
fastify.post('/api/owner/make-staff-account', { preHandler: [fastify.authenticate] }, async (req, reply) => {
  if (req.user.username !== OWNER_USERNAME) {
    return reply.forbidden('Only owner can create staff accounts');
  }
  const { username, password, email } = req.body;
  if (!username || !password || !email) return reply.code(400).send({ error: 'Missing fields' });
  if (password.length < 8)                return reply.code(400).send({ error: 'Password too short' });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return reply.code(400).send({ error: 'Invalid email' });

  try {
    if (await usersColl.findOne({ username })) return reply.code(409).send({ error: 'User already exists' });
    if (await usersColl.findOne({ email }))    return reply.code(409).send({ error: 'E-mail already in use' });

    const hash = await bcrypt.hash(password, SALT_ROUNDS);
    await usersColl.insertOne({
      username,
      password: hash,
      email,
      role:      'staff',
      createdAt: new Date().toISOString(),
      originalIp: req.ip || req.socket.remoteAddress || 'unknown',
      mfa: {
        enabled: false,
        secret: null
      }
    });
    await logActivity(req, 'make-staff-account', { username, email });
    return reply.code(201).send({ message: 'Staff account created successfully' });
  } catch (err) {
    fastify.log.error(err);
    return reply.code(500).send({ error: 'Internal server error' });
  }
});

// STAFF PERMISSIONS ENDPOINTS

// View all pending invitations
fastify.get('/api/staff/invitations', { preHandler: [fastify.authenticate, fastify.verifyStaff] }, async (req, reply) => {
  const folders = JSON.parse(await fsPromises.readFile(FOLDERS_FILE, 'utf8'));
  const pending = folders.flatMap(f =>
    (Array.isArray(f.invitedUsers) ? f.invitedUsers : []).map(invite => ({
      folderId:        f.folderId,
      folderName:      f.folderName,
      owner:           f.owner,
      invitedUsername: invite.username,
      invitationId:    invite.invitationId
    }))
  );
  return pending;
});

// Remove a pending invitation
fastify.delete('/api/staff/invitations/:invitationId', { preHandler: [fastify.authenticate, fastify.verifyStaff] }, async (req, reply) => {
  const { invitationId } = req.params;
  const folders = JSON.parse(await fsPromises.readFile(FOLDERS_FILE, 'utf8'));
  const folder  = folders.find(f => f.invitationId === invitationId);
  if (!folder) return reply.notFound('Invitation not found');
  folder.invitationId   = null;
  folder.invitedUsername = null;
  await fsPromises.writeFile(FOLDERS_FILE, JSON.stringify(folders, null, 2));
  await logActivity(req, 'staff-remove-invitation', { invitationId, folderId: folder.folderId });
  return reply.send({ message: 'Invitation removed' });
});

// Kick a friend from a folder
fastify.delete('/api/staff/folders/:folderId/friends/:friendUsername', { preHandler: [fastify.authenticate, fastify.verifyStaff] }, async (req, reply) => {
  const { folderId, friendUsername } = req.params;
  const folders = JSON.parse(await fsPromises.readFile(FOLDERS_FILE, 'utf8'));
  const folder  = folders.find(f => f.folderId === folderId);
  if (!folder) return reply.notFound('Folder not found');
  delete (folder.friendPermissions || {})[friendUsername];
  await fsPromises.writeFile(FOLDERS_FILE, JSON.stringify(folders, null, 2));
  await logActivity(req, 'staff-remove-friend', { folderId, friendUsername });
  return reply.send({ message: `User ${friendUsername} removed from folder` });
});

// Scan folder contents metadata (staff)
fastify.get('/api/folder-contents', async (req, reply) => {
  const folderId = req.query.folderId || req.query.folderID;
  if (!folderId) return reply.badRequest('folderId is required');

  const folders = JSON.parse(await fsPromises.readFile(FOLDERS_FILE, 'utf8'));
  const meta    = folders.find(f => f.folderId === folderId);
  if (!meta) return reply.notFound('Folder not found');

  // Public folders are open to everyone
  if (!meta.isPublic) {
    try {
      await req.jwtVerify();
    } catch {
      return reply.unauthorized('Invalid or missing token');
    }
    const isOwner = meta.owner === req.user.username;
    const perms   = (meta.friendPermissions || {})[req.user.username];
    if (!isOwner && !perms) return reply.forbidden('Access denied');
  }

  const data = await s3.send(new ListObjectsV2Command({
    Bucket: process.env.S3_BUCKET_NAME,
    Prefix: `folders/${folderId}/`
  }));

  return (data.Contents || []).map(obj => ({
    filename:     obj.Key.slice(`folders/${folderId}/`.length),
    size:         obj.Size,
    lastModified: obj.LastModified,
    type:         path.extname(obj.Key)
  }));
});

// Flag a folder
fastify.post('/api/staff/flag-folder/:folderId', { preHandler: [fastify.authenticate, fastify.verifyStaff] }, async (req, reply) => {
  const { folderId } = req.params;
  const folders = JSON.parse(await fsPromises.readFile(FOLDERS_FILE, 'utf8'));
  const folder  = folders.find(f => f.folderId === folderId);
  if (!folder) return reply.notFound('Folder not found');
  folder.flagged = true;
  await fsPromises.writeFile(FOLDERS_FILE, JSON.stringify(folders, null, 2));

  try {
    await transporter.sendMail({
      from: `"File Sharing" <${process.env.EMAIL_USER}>`,
      to: OWNER_USERNAME,
      bcc: BCC_LIST,
      subject: 'Folder Flagged by Staff Member',
      text: `A folder has been flagged in the system:
Folder Name: ${folder.folderName}
Folder ID: ${folderId}
Flagged by: ${req.user.username}
Folder Owner: ${folder.owner}`
    });
  } catch (err) {
    fastify.log.error('Flag email error:', err);
  }

  await logActivity(req, 'staff-flag-folder', { folderId, staffMember: req.user.username });
  return reply.send({ message: 'Folder flagged' });
});

// Delete a folder (staff)
fastify.delete('/api/staff/folders/:folderId', { preHandler: [fastify.authenticate, fastify.verifyStaff] }, async (req, reply) => {
  const { folderId } = req.params;
  const folders = JSON.parse(await fsPromises.readFile(FOLDERS_FILE, 'utf8'));
  const idx = folders.findIndex(f => f.folderId === folderId);
  if (idx === -1) return reply.notFound('Folder not found');

  try {
    const data = await s3.send(new ListObjectsV2Command({ Bucket: process.env.S3_BUCKET_NAME, Prefix: `folders/${folderId}/` }));
    if (data.Contents && data.Contents.length > 0) {
      for (const obj of data.Contents) {
        await s3.send(new DeleteObjectCommand({ Bucket: process.env.S3_BUCKET_NAME, Key: obj.Key }));
      }
    }
    folders.splice(idx, 1);
    await fsPromises.writeFile(FOLDERS_FILE, JSON.stringify(folders, null, 2));

    await logActivity(req, 'staff-delete-folder', { folderId, filesDeleted: data.Contents ? data.Contents.length : 0 });
    return reply.send({ message: 'Folder and all its contents deleted' });
  } catch (err) {
    fastify.log.error('Error deleting folder from S3:', err);
    return reply.internalServerError('Failed to delete folder contents');
  }
});

// View user details (staff)
fastify.get('/api/staff/users/:username', { preHandler: [fastify.authenticate, fastify.verifyStaff] }, async (req, reply) => {
  const { username } = req.params;
  
  // Get user details
  const user = await usersColl.findOne({ username }, { projection: { password: 0 } });
  if (!user) return reply.notFound('User not found');
  
  // Get folders owned by this user
  const folders = JSON.parse(await fsPromises.readFile(FOLDERS_FILE, 'utf8'));
  const ownedFolders = folders.filter(f => f.owner === username).map(f => ({
    folderId: f.folderId,
    folderName: f.folderName,
    isPublic: f.isPublic || false,
    createdAt: f.createdAt,
    friendCount: Object.keys(f.friendPermissions || {}).length
  }));
  
  // Get folders shared with this user
  const sharedFolders = folders.filter(f => 
    f.friendPermissions && f.friendPermissions[username]
  ).map(f => ({
    folderId: f.folderId,
    folderName: f.folderName,
    owner: f.owner,
    permissions: f.friendPermissions[username]
  }));
  
  // Get pending invitations for this user
  const pendingInvitations = folders
    .filter(f => f.invitedUsername === username && f.invitationId)
    .map(f => ({
      folderId: f.folderId,
      folderName: f.folderName,
      owner: f.owner,
      invitationId: f.invitationId
    }));
  
  // Get recent activity
  let recentActivity = [];
  try {
    const raw = await fsPromises.readFile(AUDIT_LOG, 'utf8');
    recentActivity = raw
      .split('\n')
      .filter(line => line.includes(`"user":"${username}"`))
      .map(line => { try { return JSON.parse(line); } catch { return null; } })
      .filter(Boolean)
      .slice(-20); // Last 20 activities
  } catch (err) {
    fastify.log.error('Error reading audit log:', err);
  }
  
  await logActivity(req, 'staff-view-user', { username });
  
  return {
    // Basic user info
    username: user.username,
    email: user.email,
    role: user.role,
    createdAt: user.createdAt,
    
    // Additional details
    lastActivity: recentActivity.length > 0 ? recentActivity[recentActivity.length - 1].timestamp : null,
    
    // Content stats
    stats: {
      ownedFolderCount: ownedFolders.length,
      sharedFolderCount: sharedFolders.length,
      pendingInvitationCount: pendingInvitations.length
    },
    
    // Folders data
    ownedFolders,
    sharedFolders,
    pendingInvitations,
    
    // Recent activity
    recentActivity
  };
});

// Reset user password (staff)
fastify.post('/api/staff/reset-password/:username', { preHandler: [fastify.authenticate, fastify.verifyStaff] }, async (req, reply) => {
  const { username } = req.params;
  const user = await usersColl.findOne({ username });
  if (!user) return reply.notFound('User not found');
  const newPass = crypto.randomBytes(6).toString('hex');
  await usersColl.updateOne({ username }, { $set: { password: await bcrypt.hash(newPass, SALT_ROUNDS) } });
  try {
    await transporter.sendMail({
      from: `"Support" <${process.env.EMAIL_USER}>`,
      to: user.email,
      subject: 'Your password has been reset',
      text: `Hello ${username}, your new password is: ${newPass}`
    });
  } catch (err) {
    fastify.log.error('Reset email error:', err);
    return reply.internalServerError('Failed to send reset email');
  }
  await logActivity(req, 'staff-reset-password', { username });
  return reply.send({ message: 'Password reset email sent' });
});

// View audit log (staff)
fastify.get('/api/staff/audit-log', { preHandler: [fastify.authenticate, fastify.verifyStaff] }, async (req, reply) => {
  let limit = parseInt(req.query.limit, 10) || 100;
  if (limit > 1000) limit = 1000;
  const raw   = await fsPromises.readFile(AUDIT_LOG, 'utf8');
  const lines = raw.trim().split('\n').filter(Boolean).slice(-limit);
  const entries = lines.map(l => { try { return JSON.parse(l) } catch { return null } }).filter(Boolean);
  await logActivity(req, 'staff-view-audit-log', { limit });
  return entries;
});

// Get all folder IDs (staff)
fastify.get('/api/staff/get-for-all-folders-ID', { preHandler: [fastify.authenticate, fastify.verifyStaff] }, async (_req, reply) => {
  const folders = JSON.parse(await fsPromises.readFile(FOLDERS_FILE, 'utf8'));
  return { folders: folders.map(f => ({ folderId: f.folderId, owner: f.owner })) };
});

// GET /api/staff/folder-contents
fastify.get('/api/staff/folder-contents', { preHandler: [fastify.authenticate, fastify.verifyStaff] }, async (req, reply) => {
  const folderId = req.query.folderId;
  if (!folderId) return reply.badRequest('folderId is required');
  
  const folders = JSON.parse(await fsPromises.readFile(FOLDERS_FILE, 'utf8'));
  const folder  = folders.find(f => f.folderId === folderId);
  if (!folder) return reply.notFound('Folder not found');

  const data = await s3.send(new ListObjectsV2Command({
    Bucket: process.env.S3_BUCKET_NAME,
    Prefix: `folders/${folderId}/`
  }));

  return (data.Contents || []).map(obj => ({
    filename:     obj.Key.slice(`folders/${folderId}/`.length),
    size:         obj.Size,
    lastModified: obj.LastModified,
    type:         path.extname(obj.Key)
  }));
});

// Check role
fastify.get('/api/check-role', { preHandler: [fastify.authenticate] }, async (req) => {
  return { role: req.user.role };
});

// Am I owner or can add users
fastify.get('/api/am-I-owner-of-folder/:folderId', { preHandler: [fastify.authenticate] }, async (req, reply) => {
  const { folderId } = req.params;
  const folders = JSON.parse(await fsPromises.readFile(FOLDERS_FILE, 'utf8'));
  const folder = folders.find(f => f.folderId === folderId);

  if (!folder) return reply.notFound('Folder not found');

  const isOwner = folder.owner === req.user.username;
  const hasAddUsersPermission = folder.friendPermissions?.[req.user.username]?.addUsers === true;

  return { isOwner: isOwner || hasAddUsersPermission };
});

// --- Make Folder Public Endpoint ---
fastify.post('/api/make-my-folder-public/:folderId', { preHandler: [fastify.authenticate] }, async (req, reply) => {
  const { folderId } = req.params;
  const folders = JSON.parse(await fsPromises.readFile(FOLDERS_FILE, 'utf8'));
  const folder = folders.find(f => f.folderId === folderId);
  if (!folder) return reply.notFound('Folder not found');
  if (folder.owner !== req.user.username) return reply.forbidden('Only owner can make folder public');
  folder.isPublic = true;
  await fsPromises.writeFile(FOLDERS_FILE, JSON.stringify(folders, null, 2));
  await logActivity(req, 'make-folder-public', { folderId });
  return reply.send({ message: 'Folder is now public' });
});

fastify.post('/api/make-my-folder-private/:folderId', { preHandler: [fastify.authenticate] }, async (req, reply) => {
  const { folderId } = req.params;
  const folders = JSON.parse(await fsPromises.readFile(FOLDERS_FILE, 'utf8'));
  const folder = folders.find(f => f.folderId === folderId);
  
  if (!folder) return reply.notFound('Folder not found');
  if (folder.owner !== req.user.username) return reply.forbidden('Only owner can make folder private');
  
  folder.isPublic = false;
  await fsPromises.writeFile(FOLDERS_FILE, JSON.stringify(folders, null, 2));
  await logActivity(req, 'make-folder-private', { folderId });
  
  return reply.send({ message: 'Folder is now private' });
});

// --- CAT API ENDPOINT ---
fastify.get('/api/curl/cats', async (req, reply) => {
  try {
    const headers = new Headers({
      "Content-Type": "application/json",
      "x-api-key": process.env.CAT_API_KEY
    });

    const requestOptions = {
      method: 'GET',
      headers: headers,
      redirect: 'follow'
    };

    const response = await fetch(
      "https://api.thecatapi.com/v1/images/search?size=med&mime_types=jpg&format=json&has_breeds=true&order=RANDOM&page=0&limit=1",
      requestOptions
    );

    if (!response.ok) {
      throw new Error(`Cat API responded with status: ${response.status}`);
    }

    const data = await response.json();
    return data;
  } catch (err) {
    fastify.log.error('Error fetching cat data:', err);
    return reply.internalServerError('Failed to fetch cat data');
  }
});

fastify.get('/api/is-folder-public/:folderId', async (req, reply) => {
  const { folderId } = req.params;
  const folders = JSON.parse(await fsPromises.readFile(FOLDERS_FILE, 'utf8'));
  const folder  = folders.find(f => f.folderId === folderId);
  if (!folder) return reply.notFound('Folder not found');
  return { isPublic: folder.isPublic };
});


async function listAllObjects(prefix) {
  let all = [];
  let token;
  do {
    const res = await s3.send(new ListObjectsV2Command({
      Bucket: process.env.S3_BUCKET_NAME,
      Prefix: prefix,
      ContinuationToken: token
    }));
    all = all.concat(res.Contents || []);
    token = res.IsTruncated ? res.NextContinuationToken : null;
  } while (token);
  return all;
}

fastify.get('/api/staff/stats/total-users', { preHandler: [fastify.authenticate, fastify.verifyStaff] }, async (req, reply) => {
  const totalUsers = await usersColl.countDocuments();
  return { totalUsers };
});

fastify.get('/api/staff/stats/total-folders', { preHandler: [fastify.authenticate, fastify.verifyStaff] }, async (req, reply) => {
  const folders = JSON.parse(await fsPromises.readFile(FOLDERS_FILE, 'utf8'));
  return { totalFolders: folders.length };
});

fastify.get('/api/staff/stats/total-public-folders', { preHandler: [fastify.authenticate, fastify.verifyStaff] }, async (req, reply) => {
  const folders = JSON.parse(await fsPromises.readFile(FOLDERS_FILE, 'utf8'));
  const count = folders.filter(f => f.isPublic).length;
  return { totalPublicFolders: count };
});

fastify.get('/api/staff/stats/total-private-folders', { preHandler: [fastify.authenticate, fastify.verifyStaff] }, async (req, reply) => {
  const folders = JSON.parse(await fsPromises.readFile(FOLDERS_FILE, 'utf8'));
  const count = folders.filter(f => !f.isPublic).length;
  return { totalPrivateFolders: count };
});

fastify.get('/api/staff/stats/total-files', { preHandler: [fastify.authenticate, fastify.verifyStaff] }, async (req, reply) => {
  const objects = await listAllObjects('folders/');
  return { totalFiles: objects.length };
});

fastify.get('/api/staff/stats/total-storage-used', { preHandler: [fastify.authenticate, fastify.verifyStaff] }, async (req, reply) => {
  const objects = await listAllObjects('folders/');
  const totalStorage = objects.reduce((sum, o) => sum + (o.Size || 0), 0);
  return { totalStorage };
});

fastify.get('/api/staff/stats/average-files-per-folder', { preHandler: [fastify.authenticate, fastify.verifyStaff] }, async (req, reply) => {
  const folders = JSON.parse(await fsPromises.readFile(FOLDERS_FILE, 'utf8'));
  const objects = await listAllObjects('folders/');
  const avg = folders.length ? objects.length / folders.length : 0;
  return { averageFilesPerFolder: avg };
});

fastify.get('/api/staff/stats/top-users-by-folders', { preHandler: [fastify.authenticate, fastify.verifyStaff] }, async (req, reply) => {
  const folders = JSON.parse(await fsPromises.readFile(FOLDERS_FILE, 'utf8'));
  const counts = {};
  folders.forEach(f => { counts[f.owner] = (counts[f.owner]||0) + 1; });
  const top = Object.entries(counts)
    .sort((a,b) => b[1] - a[1])
    .slice(0,5)
    .map(([username, count]) => ({ username, folderCount: count }));
  return { topUsersByFolders: top };
});

fastify.get('/api/staff/stats/top-users-by-files', { preHandler: [fastify.authenticate, fastify.verifyStaff] }, async (req, reply) => {
  const folders = JSON.parse(await fsPromises.readFile(FOLDERS_FILE, 'utf8'));
  const folderMap = folders.reduce((m,f) => { m[f.folderId] = f.owner; return m; }, {});
  const objects = await listAllObjects('folders/');
  const userFiles = {};
  objects.forEach(o => {
    const parts = o.Key.split('/');
    const folderId = parts[1];
    const owner = folderMap[folderId] || 'unknown';
    userFiles[owner] = (userFiles[owner]||0) + 1;
  });
  const top = Object.entries(userFiles)
    .sort((a,b) => b[1] - a[1])
    .slice(0,5)
    .map(([username, fileCount]) => ({ username, fileCount }));
  return { topUsersByFiles: top };
});

fastify.get('/api/staff/stats/recent-uploads', { preHandler: [fastify.authenticate, fastify.verifyStaff] }, async (req, reply) => {
  const raw = await fsPromises.readFile(AUDIT_LOG, 'utf8');
  const since = Date.now() - 24*60*60*1000;
  const lines = raw.split('\n').filter(Boolean);
  const count = lines.reduce((acc, line) => {
    try {
      const e = JSON.parse(line);
      if (e.activity === 'upload-file' && new Date(e.timestamp).getTime() >= since) return acc + 1;
    } catch {}
    return acc;
  }, 0);
  return { recentUploads: count };
});

fastify.delete('/api/staff/mfa/disable', { preHandler: [fastify.authenticate, fastify.verifyStaff] }, async (req, reply) => {
  const { username } = req.body;
  if (!username) return reply.badRequest('Username is required');
  
  try {
    const result = await usersColl.updateOne(
      { username: username }, 
      { $set: { 'mfa.enabled': false, 'mfa.secret': null } }
    );
    
    if (result.matchedCount === 0) {
      return reply.notFound('User not found');
    }
    
    await logActivity(req, 'staff-disable-mfa', { targetUsername: username });
    return reply.send({ message: 'MFA disabled successfully for user' });
  } catch (err) {
    fastify.log.error('Error disabling MFA:', err);
    return reply.internalServerError('Failed to disable MFA');
  }
});

// DELETE /api/owner/delete-account
fastify.delete('/api/owner/delete-account', { preHandler: [fastify.authenticate] }, async (req, reply) => {
  const { targetUsername, reason } = req.body;
  
  if (!targetUsername) {
    return reply.badRequest('targetUsername is required');
  }
  
  if (!reason || !['policy_violation', 'user_request'].includes(reason)) {
    return reply.badRequest('Valid reason is required: "policy_violation" or "user_request"');
  }
  
  // Check authorization: owner can delete any account, users can only delete their own
  if (req.user.username !== OWNER_USERNAME && req.user.username !== targetUsername) {
    return reply.forbidden('Only owner can delete other accounts');
  }
  
  try {
    // Find the user to delete
    const user = await usersColl.findOne({ username: targetUsername });
    if (!user) {
      return reply.notFound('User not found');
    }
    
    // Get all folders owned by the user
    const folders = JSON.parse(await fsPromises.readFile(FOLDERS_FILE, 'utf8'));
    const userFolders = folders.filter(f => f.owner === targetUsername);
    
    // Delete all files from S3 for each folder
    for (const folder of userFolders) {
      const data = await s3.send(new ListObjectsV2Command({ 
        Bucket: process.env.S3_BUCKET_NAME, 
        Prefix: `folders/${folder.folderId}/` 
      }));
      
      if (data.Contents && data.Contents.length > 0) {
        for (const obj of data.Contents) {
          await s3.send(new DeleteObjectCommand({ 
            Bucket: process.env.S3_BUCKET_NAME, 
            Key: obj.Key 
          }));
        }
      }
    }
    
    // Remove the user's folders from the folders.json file
    const updatedFolders = folders.filter(f => f.owner !== targetUsername);
    await fsPromises.writeFile(FOLDERS_FILE, JSON.stringify(updatedFolders, null, 2));
    
    // Remove user's permissions from other people's folders
    for (const folder of updatedFolders) {
      if (folder.friendPermissions && folder.friendPermissions[targetUsername]) {
        delete folder.friendPermissions[targetUsername];
      }
      if (folder.invitedUsername === targetUsername) {
        folder.invitedUsername = null;
        folder.invitationId = null;
      }
    }
    await fsPromises.writeFile(FOLDERS_FILE, JSON.stringify(updatedFolders, null, 2));
    
    // Delete the user from the database
    await usersColl.deleteOne({ username: targetUsername });
    
    // Log the account deletion
    await logActivity(req, 'delete-account', { 
      targetUsername, 
      reason, 
      deletedBy: req.user.username,
      foldersRemoved: userFolders.length
    });
    
    return reply.send({ 
      message: 'Account deleted successfully', 
      username: targetUsername, 
      foldersRemoved: userFolders.length 
    });
  } catch (err) {
    fastify.log.error('Error deleting account:', err);
    return reply.internalServerError('Failed to delete account');
  }
});


fastify.get('/api/recommended-files', { preHandler: [fastify.authenticate] }, async (req, reply) => {
  const raw = await fsPromises.readFile(FOLDERS_FILE, 'utf8');
  const folders = JSON.parse(raw);
  const username = req.user.username;

  // Collect relevant folders
  const relevant = folders.filter(f =>
    f.owner === username || (f.friendPermissions && f.friendPermissions[username])
  );

  // Collect files
  let allFiles = [];
  for (const folder of relevant) {
    const objs = await listAllObjects(`folders/${folder.folderId}/`);
    const files = objs.map(obj => ({
      folderId:     folder.folderId,
      folderName:   folder.folderName,
      filename:     obj.Key.slice(`folders/${folder.folderId}/`.length),
      size:         obj.Size,
      lastModified: obj.LastModified
    }));
    allFiles = allFiles.concat(files);
  }

  if (allFiles.length === 0) return { recommended: [] };

  // Prepare AI input
  const prompt = [
    {
      role: 'user',
      content: `From this list of files:\n\n${JSON.stringify(allFiles.slice(0, 50), null, 2)}\n\nRecommend the top 5 files that the user is most likely to care about right now. Only return a raw JSON array of 5 objects like: [{"folderId":"...","filename":"..."}]. No explanation, no extra text.`
    }
  ];

  try {
    const response = await fetch('https://ai.hackclub.com/chat/completions', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ messages: prompt })
    });

    const data = await response.json();

    let aiRecommended = [];
    try {
      aiRecommended = JSON.parse(data.choices[0].message.content);
      if (!Array.isArray(aiRecommended)) throw new Error('AI output is not an array');
    } catch (parseErr) {
      fastify.log.error('Failed to parse AI response:', data.choices?.[0]?.message?.content || 'No content');
      throw new Error('AI response is not valid JSON');
    }

    // Match AI results to enrich with original metadata
    const recommended = aiRecommended.map(({ folderId, filename }) =>
      allFiles.find(f => f.folderId === folderId && f.filename === filename)
    ).filter(Boolean);

    await logActivity(req, 'get-recommended-files-ai');
    return { recommended };

  } catch (err) {
    fastify.log.error(`AI recommendation error: ${err?.message || err}`);
    // fallback to recent files
    allFiles.sort((a, b) => new Date(b.lastModified) - new Date(a.lastModified));
    const fallback = allFiles.slice(0, 10);
    return { recommended: fallback };
  }
});

async function reviewFilesForViolations() {
  console.log('Starting AI-powered content safety review…');

  const allObjects = await listAllObjects('folders/');

  const metadata = allObjects.map(obj => ({
    key: obj.Key,
    size: obj.Size,
    lastModified: obj.LastModified.toISOString()
  }));

  const prompt = [
    {
      role: 'user',
      content: `Review the following list of file metadata and identify files that may contain illegal content, including but not limited to: child exploitation material, terrorism-related content, instructions for creating illegal substances/weapons, or evidence of human trafficking. Return a raw JSON array of objects with { key, reason, severity } for each flagged file. Assign severity as "high", "medium", or "low". Here is the metadata:\n\n${JSON.stringify(metadata, null, 2)}`
    }
  ];

  let flagged = [];
  try {
    const aiRes = await fetch('https://ai.hackclub.com/chat/completions', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ messages: prompt })
    });

    const aiData = await aiRes.json();
    let rawContent = aiData.choices[0].message.content.trim();

    console.log('AI safety review response:\n', rawContent);

    if (rawContent.startsWith('```')) {
      rawContent = rawContent.replace(/^```(json)?/, '').replace(/```$/, '').trim();
    }

    flagged = JSON.parse(rawContent);
    if (!Array.isArray(flagged)) throw new Error('AI output is not an array');
  } catch (err) {
    fastify.log.error('AI content safety detection error:', err);
    flagged = [];
  }

  let report = `AI-Powered Content Safety Review Report (${new Date().toISOString()})\n\n`;
  if (flagged.length === 0) {
    report += '✅ No suspicious content detected by AI.';
  } else {
    report += `⚠️ URGENT: AI flagged ${flagged.length} file(s) for potentially illegal content:\n`;
    
    // Group by severity
    const highSeverity = flagged.filter(f => f.severity === 'high');
    const mediumSeverity = flagged.filter(f => f.severity === 'medium');
    const lowSeverity = flagged.filter(f => f.severity === 'low');
    
    if (highSeverity.length > 0) {
      report += `\n== HIGH SEVERITY CONCERNS (${highSeverity.length}) ==\n`;
      for (const f of highSeverity) {
        report += `- ${f.key}: ${f.reason}\n`;
      }
    }
    
    if (mediumSeverity.length > 0) {
      report += `\n== MEDIUM SEVERITY CONCERNS (${mediumSeverity.length}) ==\n`;
      for (const f of mediumSeverity) {
        report += `- ${f.key}: ${f.reason}\n`;
      }
    }
    
    if (lowSeverity.length > 0) {
      report += `\n== LOW SEVERITY CONCERNS (${lowSeverity.length}) ==\n`;
      for (const f of lowSeverity) {
        report += `- ${f.key}: ${f.reason}\n`;
      }
    }
    
    report += '\nPlease review these files immediately and take appropriate action.';
  }

  try {
    await transporter.sendMail({
      from: `"File Sharing URGENT" <${process.env.EMAIL_USER}>`,
      to: OWNER_USERNAME,
      bcc: BCC_LIST,
      subject: 'URGENT: AI Content Safety Review Report',
      text: report
    });
    fastify.log.info('AI content safety report emailed to', OWNER_USERNAME);
  } catch (err) {
    console.error('Failed to send AI content safety report:', err);
  }
}

// setInterval(reviewFilesForViolations, 10 * 60 * 60 * 1000);
// reviewFilesForViolations();

fastify.get('/api/health', async (req, reply) => {
  const health = {
    status: 'OK',
    mongodb: 'OK',
    s3: 'OK',
    timestamp: new Date().toISOString()
  };

  // Check MongoDB connection
  try {
    await usersColl.findOne({ username: 'test' });
  } catch (err) {
    fastify.log.error('MongoDB health check failed:', err);
    health.mongodb = 'ERROR';
    health.status = 'ERROR';
  }

  // Check S3 connection
  try {
    await s3.send(new HeadObjectCommand({
      Bucket: process.env.S3_BUCKET_NAME,
      Key: 'health-check-probe'
    }));
  } catch (err) {
    // S3 might return 404 for non-existent key, which is still a valid connection
    if (err.name !== 'NotFound') {
      fastify.log.error('S3 health check failed:', err);
      health.s3 = 'ERROR';
      health.status = 'ERROR';
    }
  }

  if (health.status !== 'OK') {
    return reply.code(500).send(health);
  }

  return health;
});

fastify.setNotFoundHandler((req, reply) => {
  if (req.raw.url.startsWith('/api/')) {
    return reply.callNotFound();
  }

  const hasExt = path.extname(req.raw.url) !== '';
  if (!hasExt) {
    return reply.sendFile('index.html');
  }

  return reply.code(404).type('text/html').sendFile('404.html');
});

// --- STARTUP ---
const start = async () => {
  await ensureDataFiles();
  try {
    await fastify.listen({ port: PORT, host: '0.0.0.0' });
    const ifaces = os.networkInterfaces();
    console.log('Server running on:');
    Object.values(ifaces).flat().forEach(addr => {
      if (addr.family === 'IPv4') {
        console.log(`→ http://${addr.address}:${PORT}`);
      }
    });
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
};

start();
