// index.js

require('dotenv').config();

const path                = require('path');
const fs                  = require('fs').promises;
const { createReadStream, appendFile }= require('fs');
const crypto              = require('crypto');
const bcrypt              = require('bcrypt');
const fastify             = require('fastify')({
  logger: { level: process.env.LOG_LEVEL || 'info' }
});
const nodemailer          = require('nodemailer');
const transporter         = nodemailer.createTransport({
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
const os              = require('os');
const mime            = require('mime-types');

// --- CONFIGURATION ---
const PORT             = process.env.PORT || 3000;
const JWT_SECRET       = process.env.JWT_SECRET;
const TOKEN_EXPIRATION = process.env.TOKEN_EXPIRATION || '2h';
const SALT_ROUNDS      = parseInt(process.env.SALT_ROUNDS, 10) || 12;
const RATE_LIMIT_MAX   = parseInt(process.env.RATE_LIMIT_MAX, 10) || 100;
const RATE_LIMIT_WIN   = process.env.RATE_LIMIT_WINDOW || '1 minute';
const BCC_LIST         = process.env.BCC
  ? process.env.BCC.split(',').map(a => a.trim())
  : [];

if (!JWT_SECRET) {
  fastify.log.error('Missing JWT_SECRET in .env');
  process.exit(1);
}

// --- PATHS & CONSTANTS ---
const USERS_FILE    = path.join(__dirname, 'users.json');
const FOLDERS_FILE  = path.join(__dirname, 'folders.json');
const FOLDERS_DIR   = path.join(__dirname, 'folders');
const AUDIT_LOG     = path.join(__dirname, 'audit.log');
const MAX_FILE_SIZE = 100 * 1024 * 1024; // 100MB

// --- PLUGINS ---
fastify.register(fastifyCors, { origin: '*', methods: ['GET','POST','PUT','DELETE'] });
fastify.register(formbody);
fastify.register(multipart, { limits: { fileSize: MAX_FILE_SIZE, files: 1 } });
fastify.register(fastifySensible);
fastify.register(fastifyJwt,   { secret: JWT_SECRET, sign: { expiresIn: TOKEN_EXPIRATION } });
fastify.register(rateLimit,     { max: RATE_LIMIT_MAX, timeWindow: RATE_LIMIT_WIN });
fastify.register(fastifyStatic, { root: path.join(__dirname), prefix: '/', wildcard: false });

// --- AUTH DECORATOR ---
fastify.decorate('authenticate', async (req, reply) => {
  try {
    await req.jwtVerify();
  } catch {
    reply.unauthorized('Invalid or missing token');
  }
});

// --- AUDIT LOGGING ---
async function logActivity(req, activity, details = {}) {
  const ip    = req.ip || req.socket.remoteAddress || 'unknown';
  const user  = req.user?.username || details.username || 'anonymous';
  const entry = {
    timestamp: new Date().toISOString(),
    ip, user, activity, method: req.method, url: req.url, ...details
  };
  try {
    await fs.appendFile(AUDIT_LOG, JSON.stringify(entry) + '\n');
  } catch (err) {
    fastify.log.error(`Failed to write audit log: ${err.message}`);
  }
}

// --- BOOTSTRAP ---
async function ensureDataFiles() {
  try { await fs.access(USERS_FILE);    } catch { await fs.writeFile(USERS_FILE,    '{}',      'utf8'); fastify.log.info('Created users.json'); }
  try { await fs.access(FOLDERS_FILE);  } catch { await fs.writeFile(FOLDERS_FILE,  '[]',      'utf8'); fastify.log.info('Created folders.json'); }
  try { await fs.access(FOLDERS_DIR);   } catch { await fs.mkdir(FOLDERS_DIR, { recursive: true }); fastify.log.info('Created folders directory'); }
  try { await fs.access(AUDIT_LOG);     } catch { await fs.writeFile(AUDIT_LOG,     '',        'utf8'); fastify.log.info('Created audit.log'); }
}

// --- GLOBAL HOOK ---
fastify.addHook('onResponse', async (req, reply) => {
  await logActivity(req, 'request-complete', { statusCode: reply.statusCode });
});

// --- DOWNLOAD TOKENS ---
const downloadTokens = new Map();
function makeDownloadToken(folderId, filename) {
  const token = crypto.randomBytes(32).toString('hex');
  downloadTokens.set(token, { folderId, filename, expires: Date.now() + 5*60*1000 });
  return token;
}
function consumeDownloadToken(token) {
  const data = downloadTokens.get(token);
  if (!data || Date.now() > data.expires) { downloadTokens.delete(token); return null; }
  downloadTokens.delete(token);
  return data;
}

// --- ROUTES ---

// Register
fastify.post('/api/register', async (req, reply) => {
  const { username, password, email } = req.body;
  if (!username||!password||!email) return reply.code(400).send({ error:'Missing fields' });
  if (password.length<8)            return reply.code(400).send({ error:'Password too short' });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return reply.code(400).send({ error:'Invalid email' });
  const users = JSON.parse(await fs.readFile(USERS_FILE, 'utf8'));
  if (users[username]) return reply.code(409).send({ error:'User exists' });
  users[username] = { password: await bcrypt.hash(password,SALT_ROUNDS), email, role:'user', createdAt:new Date().toISOString() };
  await fs.writeFile(USERS_FILE, JSON.stringify(users,null,2),'utf8');
  await logActivity(req,'register',{username,email});
  return reply.code(201).send({ message:'User registered' });
});

// Login
fastify.post('/api/login', async (req, reply) => {
  const { username, password } = req.body;
  if (!username||!password) return reply.badRequest('Missing credentials');
  const users = JSON.parse(await fs.readFile(USERS_FILE, 'utf8'));
  const user  = users[username];
  if (!user || !(await bcrypt.compare(password,user.password))) {
    return reply.unauthorized('Invalid credentials');
  }
  const token = fastify.jwt.sign({ username, role:user.role });
  await logActivity(req,'login',{username});
  return { message:'Login successful', token, user:{ username, email:user.email, role:user.role } };
});

fastify.get('/api/my-folders', { preHandler:[fastify.authenticate] }, async (req) => {
  const folders = JSON.parse(await fs.readFile(FOLDERS_FILE,'utf8'));
  return folders.filter(f=>f.owner===req.user.username).map(f=>({ folderId:f.folderId, folderName:f.folderName }));
});

// List own folders
fastify.get('/api/folders', { preHandler:[fastify.authenticate] }, async (req) => {
  const folders = JSON.parse(await fs.readFile(FOLDERS_FILE,'utf8'));
  return folders.filter(f=>f.owner===req.user.username);
});

// Create folder
fastify.post('/api/create-folder', { preHandler:[fastify.authenticate] }, async (req, reply) => {
  let { folderName } = req.body;
  if (!folderName || typeof folderName!=='string') return reply.badRequest('folderName required');
  folderName=folderName.trim();
  if (!/^[\w\- ]{3,50}$/.test(folderName)) return reply.badRequest('Invalid folderName');
  const folders = JSON.parse(await fs.readFile(FOLDERS_FILE,'utf8'));
  if (folders.some(f=>f.folderName.toLowerCase()===folderName.toLowerCase()&&f.owner===req.user.username)) {
    return reply.conflict('Folder exists');
  }
  const folderId = crypto.randomBytes(16).toString('hex');
  await fs.mkdir(path.join(FOLDERS_DIR,folderId),{recursive:true});
  folders.push({
    folderId, folderName, owner:req.user.username, createdAt:new Date().toISOString(),
    permissions:{}, invitations:{}
  });
  await fs.writeFile(FOLDERS_FILE, JSON.stringify(folders,null,2));
  await logActivity(req,'create-folder',{folderName,folderId});
  return { message:'Folder created', folderId };
});

// Folder contents (view)
fastify.get('/api/folder-contents',{preHandler:[fastify.authenticate]},async(req,reply)=>{
  const folderId = req.query.folderID;
  if (!folderId) return reply.badRequest('folderID required');
  const folders=JSON.parse(await fs.readFile(FOLDERS_FILE,'utf8'));
  const meta=folders.find(f=>f.folderId===folderId);
  if(!meta) return reply.notFound('Folder not found');
  const isOwner = meta.owner===req.user.username;
  const canView = Boolean(meta.permissions?.[req.user.username]?.view);
  if(!isOwner&& !canView) return reply.forbidden('No view permission');
  const files=await fs.readdir(path.join(FOLDERS_DIR,folderId));
  const list=await Promise.all(files.map(async file=>{
    const stats=await fs.stat(path.join(FOLDERS_DIR,folderId,file));
    return { filename:file, size:stats.size, created:stats.birthtime, modified:stats.mtime, type:path.extname(file) };
  }));
  return list;
});

// Upload file (edit)
fastify.post('/api/upload-file/:folderId',{preHandler:[fastify.authenticate]},async(req,reply)=>{
  const { folderId } = req.params;
  const upload      = await req.file();
  if (!upload) return reply.badRequest('No file');
  if (upload.file.truncated) return reply.entityTooLarge('Too large');
  const folders=JSON.parse(await fs.readFile(FOLDERS_FILE,'utf8'));
  const meta=folders.find(f=>f.folderId===folderId);
  if(!meta) return reply.notFound('Folder not found');
  const isOwner = meta.owner===req.user.username;
  const canEdit = Boolean(meta.permissions?.[req.user.username]?.edit);
  if(!isOwner&& !canEdit) return reply.forbidden('No edit permission');
  const filename=`${Date.now()}-${upload.filename}`;
  const dest=path.join(FOLDERS_DIR,folderId,filename);
  await fs.mkdir(path.dirname(dest),{recursive:true});
  await new Promise((res,rej)=>{
    const ws=require('fs').createWriteStream(dest);
    upload.file.pipe(ws).on('finish',res).on('error',rej);
  });
  await logActivity(req,'upload-file',{folderId,filename,uploadedBy:req.user.username});
  return { message:'File uploaded', filename };
});

// Generate download token (download)
fastify.get('/api/generate-download-token',{preHandler:[fastify.authenticate]},async(req,reply)=>{
  const { folderID, filename } = req.query;
  if(!folderID||!filename) return reply.badRequest('Missing params');
  const folders=JSON.parse(await fs.readFile(FOLDERS_FILE,'utf8'));
  const meta=folders.find(f=>f.folderId===folderID);
  if(!meta) return reply.notFound('Folder not found');
  const isOwner = meta.owner===req.user.username;
  const canDownload = Boolean(meta.permissions?.[req.user.username]?.download);
  if(!isOwner&& !canDownload) return reply.forbidden('No download permission');
  const dir=path.join(FOLDERS_DIR,folderID);
  const filePath=path.join(dir,filename);
  if(!filePath.startsWith(dir)) return reply.forbidden();
  try{await fs.access(filePath)}catch{return reply.notFound('File not found')}
  const token=makeDownloadToken(folderID,filename);
  return { token };
});

// Download file
fastify.get('/api/download-file',async(req,reply)=>{
  const { token }=req.query;
  if(!token) return reply.badRequest('token required');
  const data=consumeDownloadToken(token);
  if(!data) return reply.forbidden('Invalid/expired token');
  const filePath=path.join(FOLDERS_DIR,data.folderId,data.filename);
  try{await fs.access(filePath)}catch{return reply.notFound('File not found')}
  await logActivity(req,'download-file',{folderId:data.folderId,filename:data.filename});
  reply.header('Content-Disposition',`attachment; filename="${data.filename}"`);
  return reply.send(createReadStream(filePath));
});

// Delete file (delete)
fastify.delete('/api/delete-file/:folderId/*',{preHandler:[fastify.authenticate]},async(req,reply)=>{
  const { folderId }=req.params;
  const filename=req.params['*'];
  const folders=JSON.parse(await fs.readFile(FOLDERS_FILE,'utf8'));
  const meta=folders.find(f=>f.folderId===folderId);
  if(!meta) return reply.notFound('Folder not found');
  const isOwner = meta.owner===req.user.username;
  const canDelete = Boolean(meta.permissions?.[req.user.username]?.delete);
  if(!isOwner&& !canDelete) return reply.forbidden('No delete permission');
  const filePath=path.join(FOLDERS_DIR,folderId,filename);
  try{
    await fs.access(filePath);
    await fs.unlink(filePath);
    await logActivity(req,'delete-file',{folderId,filename});
    return { message:'File deleted' };
  } catch {
    return reply.notFound('File not found');
  }
});

// Open file inline (view)
fastify.get('/api/open-file',{preHandler:[fastify.authenticate]},async(req,reply)=>{
  const { folderId, filename }=req.query;
  if(!folderId||!filename) return reply.badRequest('Missing params');
  const folders=JSON.parse(await fs.readFile(FOLDERS_FILE,'utf8'));
  const meta=folders.find(f=>f.folderId===folderId);
  if(!meta) return reply.notFound('Folder not found');
  const isOwner = meta.owner===req.user.username;
  const canView = Boolean(meta.permissions?.[req.user.username]?.view);
  if(!isOwner&& !canView) return reply.forbidden('No view permission');
  const filePath=path.join(FOLDERS_DIR,folderId,filename);
  try{await fs.access(filePath)}catch{return reply.notFound('File not found')}
  const ext=path.extname(filename).toLowerCase();
  const mimeType={
    '.txt':'text/plain','.pdf':'application/pdf',
    '.doc':'application/msword','.docx':'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    '.jpg':'image/jpeg','.jpeg':'image/jpeg','.png':'image/png','.gif':'image/gif','.mp4':'video/mp4'
  }[ext]||'application/octet-stream';
  await logActivity(req,'open-file',{folderId,filename});
  reply.header('Content-Type',mimeType);
  reply.header('Content-Disposition',`inline; filename="${filename}"`);
  return reply.send(createReadStream(filePath));
});

// Set permissions (owner only)
fastify.post('/api/set-permissions',{preHandler:[fastify.authenticate]},async(req,reply)=>{
  const { folderId, username, perms }=req.body;
  if(!folderId||!username||typeof perms!=='object') {
    return reply.badRequest('folderId, username and perms required');
  }
  const folders=JSON.parse(await fs.readFile(FOLDERS_FILE,'utf8'));
  const folder=folders.find(f=>f.folderId===folderId);
  if(!folder) return reply.notFound('Folder not found');
  if(folder.owner!==req.user.username) {
    return reply.forbidden('Only owner can change permissions');
  }
  folder.permissions = folder.permissions||{};
  folder.permissions[username] = {
    view:     !!perms.view,
    edit:     !!perms.edit,
    download: !!perms.download,
    delete:   !!perms.delete
  };
  await fs.writeFile(FOLDERS_FILE, JSON.stringify(folders,null,2));
  await logActivity(req,'set-permissions',{folderId,username,perms});
  return { message:'Permissions updated' };
});

// Add friend / invite (with perms)
fastify.post('/api/add-friend',{preHandler:[fastify.authenticate]},async(req,reply)=>{
  const { friendEmail, folderId, perms }=req.body;
  if(!friendEmail||!folderId) return reply.badRequest('Missing email or folder ID');
  const folders=JSON.parse(await fs.readFile(FOLDERS_FILE,'utf8'));
  const folder=folders.find(f=>f.folderId===folderId);
  if(!folder) return reply.notFound('Folder not found');
  if(folder.owner!==req.user.username) return reply.forbidden('Access denied');
  const users=JSON.parse(await fs.readFile(USERS_FILE,'utf8'));
  const entry=Object.entries(users).find(([u,d])=>d.email===friendEmail);
  if(!entry) return reply.notFound('User not found');
  const invitedUsername=entry[0];
  const invitationId=crypto.randomBytes(16).toString('hex');
  folder.invitations = folder.invitations||{};
  folder.invitations[invitedUsername] = {
    invitationId,
    perms: {
      view:     perms?.view     ?? true,
      edit:     perms?.edit     ?? false,
      download: perms?.download ?? false,
      delete:   perms?.delete   ?? false
    }
  };
  await fs.writeFile(FOLDERS_FILE, JSON.stringify(folders,null,2));
  await transporter.sendMail({
    from: `"FileShare" <${process.env.EMAIL_USER}>`,
    to: friendEmail,
    subject: `Invitation to "${folder.folderName}"`,
    text: `You have been invited by ${req.user.username} to "${folder.folderName}".\n\n`+
          `Accept: http://localhost:${PORT}/api/accept-invitation/${invitationId}\n`+
          `Deny:   http://localhost:${PORT}/api/deny-invitation/${invitationId}\n`
  });
  await logActivity(req,'send-invitation',{folderId,to:invitedUsername});
  return reply.send({ message:'Invitation sent' });
});

// Accept invitation
fastify.get('/api/accept-invitation/:invitationId',async(req,reply)=>{
  const { invitationId }=req.params;
  const folders=JSON.parse(await fs.readFile(FOLDERS_FILE,'utf8'));
  const folder=folders.find(f=>Object.values(f.invitations||{}).some(inv=>inv.invitationId===invitationId));
  if(!folder) return reply.notFound('Invitation not found');
  const [invitedUsername,inv] = Object.entries(folder.invitations)
    .find(([u,inv])=>inv.invitationId===invitationId);
  folder.permissions = folder.permissions||{};
  folder.permissions[invitedUsername] = inv.perms;
  delete folder.invitations[invitedUsername];
  await fs.writeFile(FOLDERS_FILE, JSON.stringify(folders,null,2));
  await logActivity(req,'accept-invitation',{folderId:folder.folderId,user:invitedUsername});
  return reply.send({ message:`Invitation accepted by ${invitedUsername}` });
});

// Deny invitation
fastify.get('/api/deny-invitation/:invitationId',async(req,reply)=>{
  const { invitationId }=req.params;
  const folders=JSON.parse(await fs.readFile(FOLDERS_FILE,'utf8'));
  const folder=folders.find(f=>Object.values(f.invitations||{}).some(inv=>inv.invitationId===invitationId));
  if(!folder) return reply.notFound('Invitation not found');
  const [invitedUsername] = Object.entries(folder.invitations)
    .find(([u,inv])=>inv.invitationId===invitationId);
  delete folder.invitations[invitedUsername];
  await fs.writeFile(FOLDERS_FILE, JSON.stringify(folders,null,2));
  await logActivity(req,'deny-invitation',{folderId:folder.folderId});
  return reply.send({ message:'Invitation denied' });
});

// View-file inline
fastify.get('/api/view-file/:folderId/*',{preHandler:[fastify.authenticate]},async(req,reply)=>{
  const { folderId }=req.params;
  const filename=req.params['*'];
  const folders=JSON.parse(await fs.readFile(FOLDERS_FILE,'utf8'));
  const meta=folders.find(f=>f.folderId===folderId);
  if(!meta) return reply.notFound('Folder not found');
  const isOwner = meta.owner===req.user.username;
  const canView = Boolean(meta.permissions?.[req.user.username]?.view);
  if(!isOwner&& !canView) return reply.forbidden('No view permission');
  const filePath=path.join(FOLDERS_DIR,folderId,filename);
  try{await fs.access(filePath)}catch{return reply.notFound('File not found')};
  const contentType=mime.lookup(filename)||'application/octet-stream';
  reply.header('Content-Type',contentType);
  reply.header('Content-Disposition','inline');
  return reply.send(createReadStream(filePath));
});

// Shared folders list
fastify.get('/api/shared-folders',{preHandler:[fastify.authenticate]},async(req)=>{
  const folders=JSON.parse(await fs.readFile(FOLDERS_FILE,'utf8'));
  return folders
    .filter(f=>Boolean(f.permissions?.[req.user.username]?.view))
    .map(f=>({ folderId:f.folderId, folderName:f.folderName }));
});

fastify.get('/api/verify-token' ,{ preHandler:[fastify.authenticate] }, async (req, reply) => {
  return { message:'Token valid', user:req.user };
});

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


// SPA fallback
fastify.setNotFoundHandler((req,reply)=>{
  if(req.raw.url.startsWith('/api/')) return reply.callNotFound();
  return reply.sendFile('index.html');
});

// START
const start=async()=>{
  await ensureDataFiles();
  try {
    await fastify.listen({ port:PORT, host:'0.0.0.0' });
    const ifaces=os.networkInterfaces();
    console.log('Server running on:');
    Object.entries(ifaces).forEach(([_,addrs])=>{
      addrs.forEach(a=>{ if(a.family==='IPv4') console.log(`→ http://${a.address}:${PORT}`); });
    });
  } catch(err){
    fastify.log.error(err);
    process.exit(1);
  }
};
start();
