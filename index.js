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
const sharp              = require('sharp');
const ffmpeg             = require('fluent-ffmpeg');
const ffmpegInstaller    = require('@ffmpeg-installer/ffmpeg');
const XLSX               = require('xlsx');
const archiver           = require('archiver');
const jwt                = require('jsonwebtoken');
const { ObjectId }       = require('mongodb');

// Configure ffmpeg path
ffmpeg.setFfmpegPath(ffmpegInstaller.path);

const fastify = fastifyLib({
  logger: { level: process.env.LOG_LEVEL || 'info' },
  trustProxy: true // Trust proxy headers
});

// Register static file serving with more specific configuration
fastify.register(require('@fastify/static'), {
  root: path.join(__dirname),
  prefix: '/',
  decorateReply: false,
  serve: false // Disable automatic route registration
});

// Add static file serving routes before other routes
fastify.after(() => {
  // Serve index.html at root
  fastify.get('/', (request, reply) => {
    return reply.sendFile('index.html');
  });
});

// --- MONGODB SETUP ---
const MONGO_URI = process.env.MONGO_URI;
const client    = new MongoClient(MONGO_URI);
let usersColl;
let bannedIpsColl;
let apiKeysColl;
let foldersColl;
let versionsColl;



async function initMongo() {
  try {
    await client.connect();
    const db = client.db('hackclub');
    usersColl     = db.collection('users');
    bannedIpsColl = db.collection('banned_ips');
    apiKeysColl   = db.collection('api_keys');
    foldersColl   = db.collection('folders');
    versionsColl  = db.collection('versions'); // Add versions collection
    
    // Create indexes for better query performance
    await Promise.all([
      usersColl.createIndex({ username: 1 }, { unique: true }),
      usersColl.createIndex({ email: 1 }, { unique: true }),
      usersColl.createIndex({ resetToken: 1 }),
      bannedIpsColl.createIndex({ ip: 1 }, { unique: true }),
      bannedIpsColl.createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 }),
      apiKeysColl.createIndex({ key: 1 }, { unique: true }),
      apiKeysColl.createIndex({ username: 1 }),
      foldersColl.createIndex({ folderId: 1 }, { unique: true }),
      foldersColl.createIndex({ owner: 1 }),
      foldersColl.createIndex({ isPublic: 1 }),
      foldersColl.createIndex({ folderName: 1, owner: 1 }),
      foldersColl.createIndex({ createdAt: 1 }),
      foldersColl.createIndex({ 'invitedUsers.invitationId': 1 }),
      versionsColl.createIndex({ fileId: 1, versionNumber: 1 }, { unique: true }),
      versionsColl.createIndex({ fileId: 1, isLatest: 1 })
    ]);
    
    // Migrate folders from JSON file if needed
    await migrateFoldersFromFile();
    
    fastify.log.info('✅ Connected to MongoDB');
  } catch (err) {
    fastify.log.error('❌ MongoDB connection error:', err);
    process.exit(1);
  }
}


// --- FOLDER MIGRATION ---
// Migration function to move folders from JSON file to MongoDB
async function migrateFoldersFromFile() {
  try {
    // Check if migration has already been done
    const foldersCount = await foldersColl.countDocuments();
    if (foldersCount > 0) {
      fastify.log.info('✅ Folders already exist in MongoDB, skipping migration');
      return;
    }

    // Check if the folders JSON file exists
    try {
      await fsPromises.access(FOLDERS_FILE);
    } catch (err) {
      fastify.log.info('No folders.json file found to migrate');
      return;
    }

    // Read folders from JSON file
    const foldersData = await fsPromises.readFile(FOLDERS_FILE, 'utf8');
    const folders = JSON.parse(foldersData);

    if (folders.length === 0) {
      fastify.log.info('No folders to migrate from folders.json');
      return;
    }

    // Add timestamps and ensure data integrity
    const foldersWithTimestamps = folders.map(folder => {
      return {
        ...folder,
        // Convert string dates to Date objects
        createdAt: folder.createdAt ? new Date(folder.createdAt) : new Date(),
        updatedAt: new Date(),
        migratedAt: new Date(),
        // Ensure friend permissions exist
        friendPermissions: folder.friendPermissions || {},
        // Ensure group permissions exist
        groupPermissions: folder.groupPermissions || {},
        // Ensure isPublic is a boolean
        isPublic: Boolean(folder.isPublic)
      };
    });

    // Insert all folders into MongoDB
    const result = await foldersColl.insertMany(foldersWithTimestamps);
    fastify.log.info(`✅ Successfully migrated ${result.insertedCount} folders to MongoDB`);

    // Create a backup of the original JSON file
    const backupPath = `${FOLDERS_FILE}.backup-${Date.now()}`;
    await fsPromises.copyFile(FOLDERS_FILE, backupPath);
    fastify.log.info(`✅ Created backup of folders.json at ${backupPath}`);

    // Optionally, clear the original file to avoid confusion
    // await fsPromises.writeFile(FOLDERS_FILE, JSON.stringify([], null, 2));
    // fastify.log.info('Cleared original folders.json file');

  } catch (err) {
    fastify.log.error('❌ Error migrating folders to MongoDB:', err);
    // Don't rethrow, allow the application to continue even if migration fails
  }
}

initMongo();



// --- API KEY MANAGEMENT ---
async function generateApiKey(username, description) {
  const key = crypto.randomBytes(32).toString('hex');
  const apiKey = {
    username,
    key,
    description,
    created: new Date(),
    lastUsed: null,
    usageCount: 0,
    isActive: true
  };
  
  await apiKeysColl.insertOne(apiKey);
  return key;
}

async function validateApiKey(key) {
  const apiKey = await apiKeysColl.findOne({ key, isActive: true });
  if (!apiKey) return null;
  
  await apiKeysColl.updateOne(
    { _id: apiKey._id },
    { 
      $set: { lastUsed: new Date() },
      $inc: { usageCount: 1 }
    }
  );
  return apiKey;
}

// Add this helper function before the versioning functions
async function ensureMongoInitialized() {
  if (!versionsColl) {
    throw new Error('MongoDB collections not initialized');
  }
}

// --- FILE VERSIONING ---
async function createFileVersion(fileId, originalName, versionData) {
  try {
    await ensureMongoInitialized();
    const version = {
      fileId,
      originalName,
      versionNumber: await getNextVersionNumber(fileId),
      createdAt: new Date(),
      size: versionData.size,
      mimeType: versionData.mimeType,
      hash: versionData.hash,
      s3Key: versionData.s3Key,
      metadata: versionData.metadata || {},
      isLatest: true
    };

    // Update previous version to not be latest
    await versionsColl.updateMany(
      { fileId, isLatest: true },
      { $set: { isLatest: false } }
    );

    // Insert new version
    await versionsColl.insertOne(version);
    return version;
  } catch (err) {
    fastify.log.error('Error creating file version:', err);
    throw err;
  }
}

async function getNextVersionNumber(fileId) {
  await ensureMongoInitialized();
  const latestVersion = await versionsColl.findOne(
    { fileId },
    { sort: { versionNumber: -1 } }
  );
  return latestVersion ? latestVersion.versionNumber + 1 : 1;
}

async function getFileVersions(fileId) {
  try {
    await ensureMongoInitialized();
    return await versionsColl.find({ fileId })
      .sort({ versionNumber: -1 })
      .toArray();
  } catch (err) {
    fastify.log.error('Error getting file versions:', err);
    throw err;
  }
}

async function getFileVersion(fileId, versionNumber) {
  try {
    await ensureMongoInitialized();
    return await versionsColl.findOne({ fileId, versionNumber });
  } catch (err) {
    fastify.log.error('Error getting specific file version:', err);
    throw err;
  }
}

async function restoreFileVersion(fileId, versionNumber) {
  try {
    await ensureMongoInitialized();
    const versionToRestore = await getFileVersion(fileId, versionNumber);
    if (!versionToRestore) {
      throw new Error('Version not found');
    }

    // Create new version based on the restored version
    const restoredVersion = {
      ...versionToRestore,
      _id: new ObjectId(),
      versionNumber: await getNextVersionNumber(fileId),
      createdAt: new Date(),
      restoredFrom: versionNumber,
      isLatest: true
    };

    // Update previous latest version
    await versionsColl.updateMany(
      { fileId, isLatest: true },
      { $set: { isLatest: false } }
    );

    // Insert restored version as new latest version
    await versionsColl.insertOne(restoredVersion);
    return restoredVersion;
  } catch (err) {
    fastify.log.error('Error restoring file version:', err);
    throw err;
  }
}

async function deleteFileVersion(fileId, versionNumber) {
  try {
    await ensureMongoInitialized();
    const version = await getFileVersion(fileId, versionNumber);
    if (!version) {
      throw new Error('Version not found');
    }

    // Don't allow deleting the only version
    const versionsCount = await versionsColl.countDocuments({ fileId });
    if (versionsCount <= 1) {
      throw new Error('Cannot delete the only version of a file');
    }

    // If deleting latest version, make previous version the latest
    if (version.isLatest) {
      const previousVersion = await versionsColl.findOne(
        { fileId, versionNumber: { $lt: versionNumber } },
        { sort: { versionNumber: -1 } }
      );
      if (previousVersion) {
        await versionsColl.updateOne(
          { _id: previousVersion._id },
          { $set: { isLatest: true } }
        );
      }
    }

    // Delete version from S3
    try {
      await s3.send(new DeleteObjectCommand({
        Bucket: process.env.S3_BUCKET_NAME,
        Key: version.s3Key
      }));
    } catch (s3Err) {
      fastify.log.error('Error deleting version from S3:', s3Err);
    }

    // Delete version from MongoDB
    await versionsColl.deleteOne({ fileId, versionNumber });
    return true;
  } catch (err) {
    fastify.log.error('Error deleting file version:', err);
    throw err;
  }
}

// Add versions collection to MongoDB initialization

// Add versioning endpoints
fastify.get('/api/files/:fileId/versions', async (req, reply) => {
  try {
    const { fileId } = req.params;
    const versions = await getFileVersions(fileId);
    return reply.send(versions);
  } catch (err) {
    fastify.log.error(err);
    return reply.code(500).send({ error: 'Error getting file versions' });
  }
});

fastify.post('/api/files/:fileId/versions/:versionNumber/restore', async (req, reply) => {
  try {
    const { fileId, versionNumber } = req.params;
    const restoredVersion = await restoreFileVersion(fileId, parseInt(versionNumber, 10));
    return reply.send(restoredVersion);
  } catch (err) {
    fastify.log.error(err);
    return reply.code(500).send({ error: 'Error restoring file version' });
  }
});

fastify.delete('/api/files/:fileId/versions/:versionNumber', async (req, reply) => {
  try {
    const { fileId, versionNumber } = req.params;
    await deleteFileVersion(fileId, parseInt(versionNumber, 10));
    return reply.send({ success: true });
  } catch (err) {
    fastify.log.error(err);
    return reply.code(500).send({ error: 'Error deleting file version' });
  }
});



// --- API KEY ENDPOINTS ---
fastify.post('/api/v1/keys', async (req, reply) => {
  try {
    // Verify JWT token
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return reply.code(401).send({ error: 'Authentication required' });
    }

    const decoded = jwt.verify(token, JWT_SECRET);
    const { description } = req.body;

    if (!description) {
      return reply.code(400).send({ error: 'Description is required' });
    }

    const key = await generateApiKey(decoded.username, description);
    
    // Log the activity
    await logActivity(req, 'generate-api-key', { description });

    return reply.send({ key });
  } catch (err) {
    if (err.name === 'JsonWebTokenError') {
      return reply.code(401).send({ error: 'Invalid token' });
    }
    throw err;
  }
});

fastify.get('/api/v1/keys', async (req, reply) => {
  try {
    // Verify JWT token
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return reply.code(401).send({ error: 'Authentication required' });
    }

    const decoded = jwt.verify(token, JWT_SECRET);
    
    // Get all active API keys for the user
    const keys = await apiKeysColl.find(
      { username: decoded.username, isActive: true },
      { projection: { key: 0 } } // Don't send the actual keys
    ).toArray();

    return reply.send({ keys });
  } catch (err) {
    if (err.name === 'JsonWebTokenError') {
      return reply.code(401).send({ error: 'Invalid token' });
    }
    throw err;
  }
});

fastify.delete('/api/v1/keys/:keyId', async (req, reply) => {
  try {
    // Verify JWT token
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return reply.code(401).send({ error: 'Authentication required' });
    }

    const decoded = jwt.verify(token, JWT_SECRET);
    const { keyId } = req.params;

    // Verify the key belongs to the user and deactivate it
    const result = await apiKeysColl.updateOne(
      { 
        _id: new ObjectId(keyId), 
        username: decoded.username,
        isActive: true 
      },
      { $set: { isActive: false } }
    );

    if (result.matchedCount === 0) {
      return reply.code(404).send({ error: 'API key not found' });
    }

    // Log the activity
    await logActivity(req, 'revoke-api-key', { keyId });

    return reply.send({ success: true });
  } catch (err) {
    if (err.name === 'JsonWebTokenError') {
      return reply.code(401).send({ error: 'Invalid token' });
    }
    throw err;
  }
});

// --- CONFIGURATION ---
const PORT             = process.env.PORT || 3000;
const JWT_SECRET       = process.env.JWT_SECRET;
const TOKEN_EXPIRATION = process.env.TOKEN_EXPIRATION || '2h';
const SALT_ROUNDS      = parseInt(process.env.SALT_ROUNDS, 10) || 12;
const RATE_LIMIT_MAX   = parseInt(process.env.RATE_LIMIT_MAX, 10) || 100;  // Global rate limit
const RATE_LIMIT_WIN   = process.env.RATE_LIMIT_WINDOW || '1 minute';      // Global time window
const AUTH_RATE_LIMIT  = parseInt(process.env.AUTH_RATE_LIMIT, 10) || 10;  // Auth endpoints
const UPLOAD_RATE_LIMIT = parseInt(process.env.UPLOAD_RATE_LIMIT, 10) || 5; // Upload endpoints
const BAN_DURATION_MS  = parseInt(process.env.BAN_DURATION_MS, 10) || 3600000; // 1 hour ban
const BCC_LIST         = process.env.BCC
  ? process.env.BCC.split(',').map(addr => addr.trim())
  : [];
const MFA_ISSUER       = process.env.MFA_ISSUER || 'FileShare';

if (!JWT_SECRET) {
  fastify.log.error('Missing JWT_SECRET in .env');
  process.exit(1);
}

// Configure email transporter
const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST,
  port: process.env.EMAIL_PORT,
  secure: false,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  },
  pool: true, // Use pooled connection for better performance
  maxConnections: 5, // Limit connections to avoid overwhelming the email server
  maxMessages: 100 // Limit messages per connection
});

// Helper function for non-blocking email sending
function sendEmailAsync(mailOptions) {
  // Fire and forget - no await, no callback, just handle with promises
  transporter.sendMail(mailOptions)
    .then(info => fastify.log.debug(`Email sent: ${info.messageId}`))
    .catch(err => fastify.log.error('Error sending email:', err));
}

// --- PATHS & CONSTANTS ---
const USERS_FILE    = path.join(__dirname, 'users.json');
const FOLDERS_FILE  = path.join(__dirname, 'folders.json');
const FOLDERS_DIR   = path.join(__dirname, 'folders');
const AUDIT_LOG     = path.join(__dirname, 'audit.log');
const GROUPS_FILE   = path.join(__dirname, 'groups.json');
const MAX_FILE_SIZE = 100 * 1024 * 1024; // 100MB

// --- MEMORY BASED RATE LIMITER FOR CRITICAL ENDPOINTS ---
// Much stricter than the plugin-based rate limiter, can't be bypassed
const ipRateLimiter = {
  // Track attempts by IP
  attempts: new Map(),
  
  // Track IPs that are temporarily banned
  bannedIPs: new Map(),
  
  // Configure limits for different endpoints
  limits: {
    '/api/register': { max: 5, window: 60000 },         // 5 registrations per minute
    '/api/login': { max: 10, window: 300000 },          // 10 login attempts per 5 minutes
    '/api/login-with-otp': { max: 5, window: 300000 },  // 5 OTP login attempts per 5 minutes
    '/api/request-otp': { max: 3, window: 300000 }      // 3 OTP requests per 5 minutes
  },
  
  // Clean old records every 10 minutes
  clean() {
    const now = Date.now();
    
    // Clean attempts
    for (const [ip, endpoints] of ipRateLimiter.attempts.entries()) {
      for (const [endpoint, attempts] of Object.entries(endpoints)) {
        // Remove expired attempts
        const newAttempts = attempts.filter(timestamp => 
          now - timestamp < (ipRateLimiter.limits[endpoint]?.window || 60000));
        
        if (newAttempts.length === 0) {
          delete endpoints[endpoint];
        } else {
          endpoints[endpoint] = newAttempts;
        }
      }
      
      // Remove IPs with no endpoints
      if (Object.keys(endpoints).length === 0) {
        ipRateLimiter.attempts.delete(ip);
      }
    }
    
    // Clean banned IPs
    for (const [ip, expiry] of ipRateLimiter.bannedIPs.entries()) {
      if (now > expiry) {
        ipRateLimiter.bannedIPs.delete(ip);
      }
    }
  },
  
  // Check if a request should be allowed
  check(req, reply) {
    const ip = getClientIP(req);
    const path = req.raw.url.split('?')[0];
    const now = Date.now();
    
    // Skip check for health endpoint
    if (path === '/api/health') {
      return true;
    }
    
    // Check if IP is banned in memory
    if (ipRateLimiter.bannedIPs.has(ip)) {
      const banExpiry = ipRateLimiter.bannedIPs.get(ip);
      if (now < banExpiry) {
        const remainingTime = Math.ceil((banExpiry - now) / 1000 / 60);
        reply.code(429).send({
          error: 'Too Many Requests',
          message: `Your IP is temporarily blocked. Try again in ${remainingTime} minutes.`
        });
        return false;
      } else {
        ipRateLimiter.bannedIPs.delete(ip);
      }
    }
    
    // Skip rate limiting for non-sensitive endpoints
    const matchedPath = Object.keys(ipRateLimiter.limits).find(p => path.startsWith(p));
    if (!matchedPath) {
      return true;
    }
    
    // Initialize tracking for this IP if needed
    if (!ipRateLimiter.attempts.has(ip)) {
      ipRateLimiter.attempts.set(ip, {});
    }
    
    const ipData = ipRateLimiter.attempts.get(ip);
    if (!ipData[matchedPath]) {
      ipData[matchedPath] = [];
    }
    
    // Get attempts for this endpoint
    const attempts = ipData[matchedPath];
    const { max, window } = ipRateLimiter.limits[matchedPath];
    
    // Remove expired attempts
    const validAttempts = attempts.filter(timestamp => now - timestamp < window);
    
    // Check if limit exceeded
    if (validAttempts.length >= max) {
      // If significantly over limit, ban temporarily
      if (validAttempts.length >= max * 2) {
        const banDuration = validAttempts.length >= max * 5 ? 3600000 : 600000; // 1 hour or 10 minutes
        ipRateLimiter.bannedIPs.set(ip, now + banDuration);
        
        // Also add to MongoDB banned IPs collection for persistence
        try {
          bannedIpsColl.updateOne(
            { ip },
            { 
              $set: {
                ip,
                reason: 'Automatic ban: Rate limit exceeded significantly',
                bannedAt: new Date().toISOString(),
                expiresAt: new Date(now + banDuration).toISOString(),
                bannedBy: 'system'
              }
            },
            { upsert: true }
          );
        } catch (err) {
          fastify.log.error(`Failed to ban IP ${ip} in MongoDB: ${err.message}`);
        }
        
        // Log ban action
        try {
          logActivity({ip, user: 'system'}, 'ip-auto-banned', { 
            ip, 
            endpoint: matchedPath,
            attemptCount: validAttempts.length,
            banDuration: banDuration / 60000 + ' minutes'
          });
        } catch (err) {
          fastify.log.error(`Failed to log ban: ${err.message}`);
        }
        
        const banMinutes = banDuration / 60000;
        reply.code(429).send({
          error: 'Too Many Requests',
          message: `Rate limit exceeded significantly. Your IP has been blocked for ${banMinutes} minutes.`
        });
        return false;
      }
      
      // Log rate limit action
      try {
        logActivity({ip, user: 'system'}, 'rate-limit-hit', { 
          ip, 
          endpoint: matchedPath,
          attemptCount: validAttempts.length
        });
      } catch (err) {
        fastify.log.error(`Failed to log rate limit: ${err.message}`);
      }
      
      reply.code(429).send({
        error: 'Too Many Requests',
        message: `You've made too many requests. Please try again later.`
      });
      return false;
    }
    
    // Record this attempt
    validAttempts.push(now);
    ipData[matchedPath] = validAttempts;
    
    return true;
  }
};

// Clean rate limit data periodically
setInterval(() => ipRateLimiter.clean(), 600000); // Every 10 minutes

// --- PLUGINS ---
fastify.register(require('@fastify/cors'),   { origin: '*', methods: ['GET','POST','PUT','DELETE'] });
fastify.register(require('@fastify/formbody'));
fastify.register(require('@fastify/multipart'), { limits: { fileSize: MAX_FILE_SIZE, files: 1 } });
fastify.register(require('@fastify/sensible'));
fastify.register(require('@fastify/jwt'),     { secret: JWT_SECRET, sign: { expiresIn: TOKEN_EXPIRATION } });

// Configure rate limiting plugin for general protection
fastify.register(require('@fastify/rate-limit'), {
  global: true,
  max: RATE_LIMIT_MAX,
  timeWindow: RATE_LIMIT_WIN,
  allowList: ['127.0.0.1', 'localhost'],  // Don't rate limit localhost
  keyGenerator: (req) => getClientIP(req),
  errorResponseBuilder: (req, context) => {
    return {
      statusCode: 429,
      error: 'Too Many Requests',
      message: `Rate limit exceeded. Try again in ${context.after}`,
      expiresIn: context.after
    };
  }
});

// Serve static files without requiring ".html" in URLs
fastify.register(require('@fastify/static'), {
  root: __dirname,
  prefix: '/',
  index: false,
  extensions: ['html']
});

// --- MIDDLEWARE FOR BANNED IP CHECKING AND RATE LIMITING ---
fastify.addHook('onRequest', async (req, reply) => {
  const ip = getClientIP(req);
  
  try {
    // Skip IP checks for health endpoint
    if (req.raw.url === '/api/health') {
      return;
    }

    // Check if MongoDB is initialized
    if (!bannedIpsColl) {
      fastify.log.warn('MongoDB not initialized yet, skipping IP security check');
      return;
    }
    
    // Check MongoDB for banned IPs
    const banned = await bannedIpsColl.findOne({ 
      ip, 
      expiresAt: { $gt: new Date().toISOString() } 
    });
    
    if (banned) {
      await logActivity({ip, user: 'banned'}, 'banned-ip-request-attempt', { 
        ip, 
        url: req.raw.url,
        bannedUntil: banned.expiresAt 
      });
      
      return reply.code(403).send({ 
        error: 'Access Forbidden',
        message: 'Your IP address has been temporarily blocked due to suspicious activity' 
      });
    }
    
    // Apply our custom strict rate limiter for critical endpoints
    if (!ipRateLimiter.check(req, reply)) {
      return; // Reply already sent by the rate limiter
    }
  } catch (err) {
    fastify.log.error(`Error in IP security check: ${err.message}`);
    // Continue processing the request even if the security check fails
  }
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

// Helper function to get real client IP
function getClientIP(req) {
  // Check X-Forwarded-For header first
  const forwardedFor = req.headers['x-forwarded-for'];
  if (forwardedFor) {
    // Get the first IP in the chain (client IP)
    const clientIP = forwardedFor.split(',')[0].trim();
    if (clientIP) return clientIP;
  }

  // Check X-Real-IP header
  const realIP = req.headers['x-real-ip'];
  if (realIP) return realIP;

  // Fallback to direct connection IP
  return req.ip || req.socket.remoteAddress || 'unknown';
}

// --- AUDIT LOGGING HELPER ---
async function logActivity(req, activity, details = {}) {
  const ip = getClientIP(req);
  const user = req.user?.username || details.username || 'anonymous';
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
    const GROUPS_FILE = path.join(__dirname, 'groups.json');
    await fsPromises.access(GROUPS_FILE);
  } catch {
    await fsPromises.writeFile(GROUPS_FILE, JSON.stringify([], null, 2));
    fastify.log.info('Created groups.json');

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
  const ip = getClientIP(req);
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

fastify.post('/api/request-otp', async (req, reply) => {
  const { email } = req.body;
  
  if (!email) {
    return reply.badRequest('Email is required');
  }
  
  try {
    // Find user by email
    const user = await usersColl.findOne({ email });
    if (!user) {
      // For security reasons, don't reveal if email exists or not
      return reply.send({ message: 'If your email is registered, a one-time password has been sent' });
    }
    
    // Generate a secure random OTP (6 digits)
    const otp = crypto.randomInt(100000, 999999).toString();
    
    // Hash the OTP for storage
    const hashedOtp = await bcrypt.hash(otp, 5); // Lower rounds for faster processing
    
    // Store the OTP with expiration (10 minutes)
    const expiresAt = new Date();
    expiresAt.setMinutes(expiresAt.getMinutes() + 10);
    
    await usersColl.updateOne(
      { email },
      { 
        $set: { 
          'otpLogin': {
            hashedOtp,
            expiresAt,
            attemptCount: 0
          }
        } 
      }
    );
    
    // Send the OTP via email
    sendEmailAsync({
      from: `"FileShare Security" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: 'Your One-Time Password for FileShare',
      text: `Hello ${user.username},

You have requested a one-time password to log in to your FileShare account.

Your one-time password is: ${otp}

This password will expire in 10 minutes and can only be used once.

If you did not request this login code, please ignore this email.

Thank you,
FileShare Security Team`
    });
    
    await logActivity(req, 'otp-requested', { username: user.username, email });
    
    return reply.send({ message: 'If your email is registered, a one-time password has been sent' });
  } catch (err) {
    fastify.log.error('Error generating OTP:', err);
    return reply.internalServerError('Error processing request');
  }
});

// Endpoint to validate and login with OTP
fastify.post('/api/login-with-otp', async (req, reply) => {
  const { email, otp } = req.body;
  
  if (!email || !otp) {
    return reply.badRequest('Email and OTP are required');
  }
  
  try {
    // Find user by email
    const user = await usersColl.findOne({ email });
    if (!user || !user.otpLogin || !user.otpLogin.hashedOtp) {
      return reply.unauthorized('Invalid credentials');
    }
    
    // Check if OTP is expired
    if (new Date() > new Date(user.otpLogin.expiresAt)) {
      // Clear expired OTP
      await usersColl.updateOne({ email }, { $unset: { otpLogin: "" } });
      return reply.unauthorized('OTP has expired');
    }
    
    // Check attempt count to prevent brute force
    if (user.otpLogin.attemptCount >= 5) {
      // Clear OTP after too many attempts
      await usersColl.updateOne({ email }, { $unset: { otpLogin: "" } });
      return reply.unauthorized('Too many failed attempts');
    }
    
    // Verify OTP
    const isValid = await bcrypt.compare(otp, user.otpLogin.hashedOtp);
    
    if (!isValid) {
      // Increment attempt count
      await usersColl.updateOne(
        { email }, 
        { $inc: { 'otpLogin.attemptCount': 1 } }
      );
      return reply.unauthorized('Invalid OTP');
    }
    
    // OTP is valid - clear it to prevent reuse
    await usersColl.updateOne({ email }, { $unset: { otpLogin: "" } });
    
    // Generate JWT token - same as normal login but bypassing password/MFA
    const token = fastify.jwt.sign({ username: user.username, role: user.role });
    
    await logActivity(req, 'login-with-otp');
    
    return reply.send({
      message: 'Login successful',
      token,
      user: {
        username: user.username,
        email: user.email,
        role: user.role,
        mfaEnabled: user.mfa?.enabled || false
      }
    });
  } catch (err) {
    fastify.log.error('Error logging in with OTP:', err);
    return reply.internalServerError('Error processing login');
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
  const folders = await foldersColl.find({ owner: req.user.username }).toArray();
  return folders;
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

  const exists = await foldersColl.findOne({
    folderName: { $regex: new RegExp(`^${folderName}$`, 'i') },
    owner: req.user.username
  });
  if (exists) {
    return reply.conflict('Folder already exists');
  }

  const folderId = crypto.randomBytes(16).toString('hex');
  const newFolder = {
    folderName,
    folderId,
    owner: req.user.username,
    createdAt: new Date().toISOString(),
    friendPermissions: {},
    groupPermissions: {},
    isPublic: false,
    invitedUsers: []
  };

  await foldersColl.insertOne(newFolder);
  await logActivity(req, 'create-folder', { folderName, folderId });
  return { message: 'Folder created', folderId };
});
// POST /api/upload-file/:folderId
fastify.post('/api/upload-file/:folderId', { preHandler: [fastify.authenticate] }, async (req, reply) => {
  const { folderId } = req.params;
  const upload = await req.file();

  if (!upload) return reply.badRequest('No file uploaded');
  if (upload.file.truncated) return reply.entityTooLarge('File too large');

  const folder = await foldersColl.findOne({ folderId });
  if (!folder) return reply.notFound('Folder not found');

  const isOwner = folder.owner === req.user.username;
  const perms   = (folder.friendPermissions || {})[req.user.username];

  // Check if user has upload permission through group membership
  let hasGroupUploadPermission = false;
  if (!isOwner && !perms?.upload) {
    const groups = JSON.parse(await fsPromises.readFile(GROUPS_FILE, 'utf8'));
    const myGroupIds = groups.filter(g => g.members.includes(req.user.username)).map(g => g.groupId);
    hasGroupUploadPermission = myGroupIds.some(id => folder.groupPermissions?.[id]?.upload === true);
  }

  // Public folders: only owner, users with explicit upload permission, or group members with upload permission can add files
  if (!isOwner && !perms?.upload && !hasGroupUploadPermission) {
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

  // Send email notification to folder owner if the uploader is not the owner
  if (!isOwner) {
    try {
      const owner = await usersColl.findOne({ username: folder.owner });
      if (owner && owner.email) {
        sendEmailAsync({
          from: `"File Sharing" <${process.env.EMAIL_USER}>`,
          to: owner.email,
          subject: `New File Uploaded to Your Folder: ${folder.folderName}`,
          text: `Hello ${folder.owner},\n\n${req.user.username} has uploaded a new file "${upload.filename}" to your folder "${folder.folderName}".\n\nFile details:\n- Name: ${upload.filename}\n- Size: ${formatFileSize(fileBuffer.length)}\n- Type: ${upload.mimetype || 'Unknown'}\n\nYou can view this file in your folder.\n\nThank you.`
        });
      }
    } catch (err) {
      fastify.log.error('Failed to send upload notification email:', err);
    }
  }

  await logActivity(req, 'upload-file', { folderId, filename });
  return { message: 'File uploaded', filename };
});

function formatFileSize(bytes) {
  if (!bytes) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${(bytes / Math.pow(k, i)).toFixed(2)} ${sizes[i]}`;
}

// GET /api/generate-download-token
fastify.get('/api/generate-download-token', async (req, reply) => {
  const folderId = req.query.folderId || req.query.folderID;
  const filename = req.query.filename;
  if (!folderId || !filename) return reply.badRequest('Missing params');

  const meta = await foldersColl.findOne({ folderId });
  if (!meta) return reply.notFound('Folder not found');

  // Check if folder is public first
  if (meta.isPublic) {
    // Public folders don't need authentication
    try {
      await s3.send(new HeadObjectCommand({
        Bucket: process.env.S3_BUCKET_NAME,
        Key: `folders/${folderId}/${filename}`
      }));

      const token = makeDownloadToken(folderId, filename);
      await logActivity(req, 'generate-public-download-token', { folderId, filename });
      return { token };
    } catch (err) {
      fastify.log.error('Error generating download token:', err);
      if (err.name === 'NotFound') {
        return reply.notFound('File not found');
      }
      return reply.internalServerError('Failed to generate download token');
    }
  } else {
    // Non-public folders require authentication
    try { 
      await req.jwtVerify(); 
    } catch { 
      return reply.unauthorized('Invalid or missing token'); 
    }

    let allowed = false;
    const isOwner = meta.owner === req.user.username;

    if (isOwner) {
      allowed = true;
    } else {
      const friendPerms = (meta.friendPermissions || {})[req.user.username];
      if (friendPerms?.download) allowed = true;

      if (!allowed) {
        const groups = JSON.parse(await fsPromises.readFile(GROUPS_FILE, 'utf8'));
        const myGroupIds = groups.filter(g => g.members.includes(req.user.username)).map(g => g.groupId);
        const groupPermOk = myGroupIds.some(id => meta.groupPermissions?.[id]?.download === true);
        if (groupPermOk) allowed = true;
      }
    }

    if (!allowed) return reply.forbidden('Access denied');

    try {
      await s3.send(new HeadObjectCommand({
        Bucket: process.env.S3_BUCKET_NAME,
        Key: `folders/${folderId}/${filename}`
      }));

      const token = makeDownloadToken(folderId, filename);
      await logActivity(req, 'generate-download-token', { folderId, filename });
      return { token };
    } catch (err) {
      fastify.log.error('Error generating download token:', err);
      if (err.name === 'NotFound') {
        return reply.notFound('File not found');
      }
      return reply.internalServerError('Failed to generate download token');
    }
  }
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

async function streamToBuffer(stream) {
  return Buffer.concat(await stream.transformToByteArray());
}


fastify.get('/api/export-as-zip/:folderId', { preHandler: [fastify.authenticate] }, async (req, reply) => {
  const { folderId } = req.params;
  const folder = await foldersColl.findOne({ folderId });
  if (!folder) return reply.notFound('Folder not found');
  if (folder.owner !== req.user.username) return reply.forbidden('Only folder owner can export');

  const data = await s3.send(new ListObjectsV2Command({
    Bucket: process.env.S3_BUCKET_NAME,
    Prefix: `folders/${folderId}/`
  }));
  if (!data.Contents?.length) {
    return reply.notFound('No files found in folder');
  }

  reply.raw.setHeader('Content-Type', 'application/zip');
  reply.raw.setHeader('Content-Disposition', `attachment; filename="${folder.folderName.replace(/[^a-z0-9]/gi, '_')}_export.zip"`);
  reply.raw.flushHeaders();

  const archive = archiver('zip', { zlib: { level: 5 } });
  archive.on('error', err => { fastify.log.error('Archive error:', err); reply.internalServerError('Failed to create zip'); });
  archive.pipe(reply.raw);

  for (const obj of data.Contents) {
    const filename = obj.Key.slice(`folders/${folderId}/`.length);
    if (!filename) continue;
    const resp = await s3.send(new GetObjectCommand({ Bucket: process.env.S3_BUCKET_NAME, Key: obj.Key }));
    archive.append(resp.Body, { name: filename });
  }

  await archive.finalize();
  await logActivity(req, 'export-folder-as-zip', {
    folderId,
    folderName: folder.folderName,
    fileCount: data.Contents.length
  });
});





// GET /api/open-file
fastify.get('/api/open-file', async (req, reply) => {
  const { folderId, filename } = req.query;
  if (!folderId || !filename) return reply.badRequest('Missing folderId or filename');

  const meta = await foldersColl.findOne({ folderId });
  if (!meta) return reply.notFound('Folder not found');

  let allowed = false;
  const isOwner = meta.owner === req.user?.username;

  if (meta.isPublic || isOwner) {
    allowed = true;
  } else {
    try { await req.jwtVerify(); } catch { return reply.unauthorized('Invalid or missing token'); }

    const friendPerms = (meta.friendPermissions || {})[req.user.username];
    if (friendPerms?.download) allowed = true;

    if (!allowed) {
      const groups = JSON.parse(await fsPromises.readFile(GROUPS_FILE, 'utf8'));
      const myGroupIds = groups.filter(g => g.members.includes(req.user.username)).map(g => g.groupId);
      const groupPermOk = myGroupIds.some(id => meta.groupPermissions?.[id]?.download === true);
      if (groupPermOk) allowed = true;
    }
  }

  if (!allowed) return reply.forbidden('Access denied');

  const ext      = path.extname(filename).toLowerCase();
  const mimeType = mime.lookup(ext) || 'application/octet-stream';

  const command  = new GetObjectCommand({
    Bucket: process.env.S3_BUCKET_NAME,
    Key:    `folders/${folderId}/${filename}`
  });
  const response = await s3.send(command);

  reply.header('Content-Type', mimeType);
  reply.header('Content-Disposition', `inline; filename="${filename}"`);
  return reply.send(response.Body);
});
// GET /api/view-file/:folderId/*
fastify.get('/api/view-file/:folderId/*', async (req, reply) => {
  const { folderId } = req.params;
  const filename = req.params['*'];
  const key = `folders/${folderId}/${filename}`;

  const meta = await foldersColl.findOne({ folderId });
  if (!meta) return reply.notFound('Folder not found');

  // Check if folder is public first
  if (meta.isPublic) {
    // Public folders don't need authentication
    try {
      await s3.send(new HeadObjectCommand({ Bucket: process.env.S3_BUCKET_NAME, Key: key }));
      const response = await s3.send(new GetObjectCommand({ Bucket: process.env.S3_BUCKET_NAME, Key: key }));
      
      const mimeType = mime.lookup(filename) || 'application/octet-stream';
      reply.header('Content-Type', mimeType);
      reply.header('Content-Disposition', 'inline');
      
      await logActivity(req, 'view-public-file', { folderId, filename });
      return reply.send(response.Body);
    } catch (err) {
      fastify.log.error('Error accessing file:', err);
      if (err.name === 'NotFound') {
        return reply.notFound('File not found');
      }
      return reply.internalServerError('Failed to access file');
    }
  } else {
    // Non-public folders require authentication
    try { 
      await req.jwtVerify(); 
    } catch { 
      return reply.unauthorized('Invalid or missing token'); 
    }

    let allowed = false;
    const isOwner = meta.owner === req.user.username;

    if (isOwner) {
      allowed = true;
    } else {
      const friendPerms = (meta.friendPermissions || {})[req.user.username];
      if (friendPerms?.view || friendPerms?.download) allowed = true;

      if (!allowed) {
        const groups = JSON.parse(await fsPromises.readFile(GROUPS_FILE, 'utf8'));
        const myGroupIds = groups.filter(g => g.members.includes(req.user.username)).map(g => g.groupId);
        const groupPermOk = myGroupIds.some(id => 
          meta.groupPermissions?.[id]?.view === true || 
          meta.groupPermissions?.[id]?.download === true
        );
        if (groupPermOk) allowed = true;
      }
    }

    if (!allowed) return reply.forbidden('Access denied');

    try {
      await s3.send(new HeadObjectCommand({ Bucket: process.env.S3_BUCKET_NAME, Key: key }));
      const response = await s3.send(new GetObjectCommand({ Bucket: process.env.S3_BUCKET_NAME, Key: key }));
      
      const mimeType = mime.lookup(filename) || 'application/octet-stream';
      reply.header('Content-Type', mimeType);
      reply.header('Content-Disposition', 'inline');
      
      await logActivity(req, 'view-file', { folderId, filename });
      return reply.send(response.Body);
    } catch (err) {
      fastify.log.error('Error accessing file:', err);
      if (err.name === 'NotFound') {
        return reply.notFound('File not found');
      }
      return reply.internalServerError('Failed to access file');
    }
  }
});

// GET /api/v1/file/:fileId
fastify.get('/api/v1/file/:fileId', async (req, reply) => {
  try {
    const { fileId } = req.params;
    const apiKey = req.headers['x-api-key'];
    const range = req.headers.range;

    // Parse file ID
    const [folderId, filename] = fileId.split(':', 2);
    if (!folderId || !filename) {
      return reply.code(400).send({ error: 'Invalid file ID format' });
    }

    // Load folder metadata from MongoDB
    const meta = await foldersColl.findOne({ folderId });
    if (!meta) {
      return reply.code(404).send({ error: 'Folder not found' });
    }

    // Check permissions for private folders
    if (!meta.isPublic) {
      const keyData = await validateApiKey(apiKey);
      if (!keyData) {
        return reply.code(401).send({ error: 'Invalid API key' });
      }

      // Check if user is owner or has permission
      const hasAccess = meta.owner === keyData.username || 
                       (meta.permissions && 
                        meta.permissions[keyData.username] && 
                        meta.permissions[keyData.username].download);

      if (!hasAccess) {
        return reply.code(403).send({ error: 'Access denied' });
      }

      // Update usage count
      await apiKeysColl.updateOne(
        { _id: keyData._id },
        { $inc: { usageCount: 1 } }
      );
    }

    // Get file metadata from S3
    const key = `folders/${folderId}/${filename}`;
    let headRes;
    try {
      headRes = await s3.send(new HeadObjectCommand({
        Bucket: process.env.S3_BUCKET_NAME,
        Key: key
      }));
    } catch (err) {
      if (err.name === 'NotFound' || err.name === 'NoSuchKey') {
        return reply.code(404).send({ error: 'File not found' });
      }
      throw err;
    }

    // Determine MIME type and content disposition
    const mimeType = mime.lookup(filename) || 'application/octet-stream';
    const totalSize = headRes.ContentLength;
    const fileExtension = path.extname(filename).toLowerCase();
    
    // Determine if file should be displayed inline or downloaded
    const inlineTypes = ['.pdf', '.jpg', '.jpeg', '.png', '.gif', '.svg', '.webp', '.mp4', '.webm', '.mp3', '.wav'];
    const shouldDisplayInline = inlineTypes.includes(fileExtension);
    const disposition = shouldDisplayInline ? 'inline' : 'attachment';

    // Handle range requests for partial content
    let rangeStart = 0;
    let rangeEnd = totalSize - 1;
    let isRangeRequest = false;

    if (range && totalSize > 0) {
      const rangeMatch = /bytes=(\d+)-(\d*)/.exec(range);
      if (rangeMatch) {
        rangeStart = parseInt(rangeMatch[1], 10);
        if (rangeMatch[2]) {
          rangeEnd = Math.min(parseInt(rangeMatch[2], 10), totalSize - 1);
        }
        
        // Validate range
        if (rangeStart >= totalSize || rangeStart > rangeEnd) {
          return reply
            .code(416)
            .header('Content-Range', `bytes */${totalSize}`)
            .send({ error: 'Range not satisfiable' });
        }
        
        isRangeRequest = true;
      }
    }

    // Get file content from S3
    const getObjectParams = {
      Bucket: process.env.S3_BUCKET_NAME,
      Key: key
    };

    if (isRangeRequest) {
      getObjectParams.Range = `bytes=${rangeStart}-${rangeEnd}`;
    }

    const s3Response = await s3.send(new GetObjectCommand(getObjectParams));
    
    // Convert S3 stream to Node.js readable stream
    const stream = s3Response.Body;

    // Handle stream errors
    stream.on('error', (err) => {
      fastify.log.error('Stream error while serving file:', {
        error: err.message,
        stack: err.stack,
        fileId: req.params.fileId,
        key,
        rangeStart,
        rangeEnd
      });
      // Don't need to send response here as fastify will handle it
    });

    // Set response headers
    const responseHeaders = {
      'Content-Type': mimeType,
      'Content-Disposition': `${disposition}; filename="${encodeURIComponent(filename)}"`,
      'Cache-Control': 'public, max-age=3600',
      'ETag': headRes.ETag,
      'Last-Modified': headRes.LastModified
    };

    if (isRangeRequest) {
      responseHeaders['Accept-Ranges'] = 'bytes';
      responseHeaders['Content-Range'] = `bytes ${rangeStart}-${rangeEnd}/${totalSize}`;
      responseHeaders['Content-Length'] = rangeEnd - rangeStart + 1;
    } else {
      responseHeaders['Content-Length'] = totalSize;
      responseHeaders['Accept-Ranges'] = 'bytes';
    }

    // Handle conditional requests (If-None-Match, If-Modified-Since)
    const ifNoneMatch = req.headers['if-none-match'];
    const ifModifiedSince = req.headers['if-modified-since'];

    if (ifNoneMatch === headRes.ETag || 
        (ifModifiedSince && new Date(ifModifiedSince) >= new Date(headRes.LastModified))) {
      return reply.code(304).headers(responseHeaders).send();
    }

    // Send the response
    return reply
      .code(isRangeRequest ? 206 : 200)
      .headers(responseHeaders)
      .send(stream);

  } catch (err) {
    fastify.log.error('Error serving file:', {
      error: err.message,
      stack: err.stack,
      fileId: req.params.fileId,
      key: `folders/${folderId}/${filename}`,
      s3Error: err.name,
      s3Code: err.$metadata?.httpStatusCode,
      s3RequestId: err.$metadata?.requestId
    });
    
    if (err.name === 'NoSuchKey' || err.name === 'NotFound') {
      return reply.code(404).send({ error: 'File not found' });
    }
    
    return reply.code(500).send({ error: 'Failed to serve file' });
  }
});


// GET /api/v1/folder/:folderId
fastify.get('/api/v1/folder/:folderId', async (req, reply) => {
  try {
    const { folderId } = req.params;
    const folder = await foldersColl.findOne({ folderId });
    if (!folder) return reply.notFound('Folder not found');
    return folder;
  } catch (err) {
    fastify.log.error('Error getting folder:', err);
    return reply.internalServerError('Error retrieving folder');
  }
});

// GET /api/v1/latest/:folderId
fastify.get('/api/v1/latest/:folderId', async (req, reply) => {
  const { folderId } = req.params;
  const apiKey = req.headers['x-api-key'];
  const folder = await foldersColl.findOne({ folderId });
  if (!folder) return reply.notFound('Folder not found');

  const keyData = await validateApiKey(apiKey);
  if (!keyData) return reply.code(401).send({ error: 'Invalid API key' });

  if (!folder.isPublic) {
    const hasAccess = folder.owner === keyData.username ||
      (folder.permissions?.[keyData.username]?.download);
    if (!hasAccess) return reply.forbidden('Access denied');
  }

  const data = await s3.send(new ListObjectsV2Command({
    Bucket: process.env.S3_BUCKET_NAME,
    Prefix: `folders/${folderId}/`
  }));
  if (!data.Contents?.length) return reply.notFound('No files in folder');

  const latest = data.Contents
    .filter(obj => obj.Key !== `folders/${folderId}/`)
    .sort((a,b) => b.LastModified - a.LastModified)[0];
  const filename = latest.Key.slice(`folders/${folderId}/`.length);

  await apiKeysColl.updateOne({ _id: keyData._id }, { $inc: { usageCount: 1 } });

  return reply.send({
    id: `${folderId}:${filename}`,
    name: filename,
    size: latest.Size,
    type: mime.lookup(filename) || 'application/octet-stream',
    lastModified: latest.LastModified.toISOString(),
    url: `https://hackclub.maksimmalbasa.in.rs/api/v1/file/${folderId}:${filename}`
  });
});


// POST /api/v1/upload
fastify.post('/api/v1/upload', async (req, reply) => {
  const apiKey = req.headers['x-api-key'];
  const folderId = req.query.folderId;
  if (!folderId) return reply.badRequest('folderId query parameter is required');

  const keyData = await validateApiKey(apiKey);
  if (!keyData) return reply.code(401).send({ error: 'Invalid API key' });

  const folder = await foldersColl.findOne({ folderId });
  if (!folder) return reply.notFound('Folder not found');

  const hasUpload = folder.owner === keyData.username ||
    (folder.permissions?.[keyData.username]?.upload);
  if (!hasUpload) return reply.forbidden('No upload permission');

  const uploadedFiles = [];
  for await (const file of await req.files()) {
    if (file.file.truncated) return reply.entityTooLarge('File too large');
    const filename = `${Date.now()}-${file.filename}`;
    const buf = await file.toBuffer();
    await s3.send(new PutObjectCommand({
      Bucket: process.env.S3_BUCKET_NAME,
      Key: `folders/${folderId}/${filename}`,
      Body: buf,
      ContentType: file.mimetype || mime.lookup(filename) || 'application/octet-stream',
      ContentLength: buf.length
    }));
    uploadedFiles.push({
      id: `${folderId}:${filename}`,
      name: filename,
      size: buf.length,
      type: file.mimetype || 'application/octet-stream',
      url: `https://hackclub.maksimmalbasa.in.rs/api/v1/file/${folderId}:${filename}`
    });
  }

  await apiKeysColl.updateOne({ _id: keyData._id }, { $inc: { usageCount: 1 } });
  return reply.send({ files: uploadedFiles });
});


// GET /api/v1/usage
fastify.get('/api/v1/usage', async (req, reply) => {
  const apiKey = req.headers['x-api-key'];
  const keyData = await validateApiKey(apiKey);
  if (!keyData) return reply.code(401).send({ error: 'Invalid API key' });

  const userFolders = await foldersColl.find({ owner: keyData.username }).toArray();
  let totalSize = 0, totalFiles = 0;
  for (const folder of userFolders) {
    const data = await s3.send(new ListObjectsV2Command({
      Bucket: process.env.S3_BUCKET_NAME,
      Prefix: `folders/${folder.folderId}/`
    }));
    const contents = data.Contents || [];
    totalFiles += contents.length;
    totalSize += contents.reduce((sum, obj) => sum + obj.Size, 0);
  }

  await apiKeysColl.updateOne({ _id: keyData._id }, { $inc: { usageCount: 1 } });
  return reply.send({
    apiKey: {
      created: keyData.created,
      lastUsed: keyData.lastUsed,
      totalRequests: keyData.usageCount
    },
    storage: {
      files: totalFiles,
      totalSize
    }
  });
});

// DELETE /api/delete-file/:folderId/*
fastify.delete('/api/delete-file/:folderId/*', { preHandler: [fastify.authenticate] }, async (req, reply) => {
  const { folderId } = req.params;
  const filename = req.params['*'];

  const folder = await foldersColl.findOne({ folderId });
  if (!folder) return reply.notFound('Folder not found');
  const isOwner = folder.owner === req.user.username;
  const perms   = folder.friendPermissions?.[req.user.username];

  let hasGroupDelete = false;
  if (!isOwner && !perms?.delete) {
    const groupDocs = await groupsColl.find({ members: req.user.username }).toArray();
    const myGroupIds = groupDocs.map(g => g.groupId);
    hasGroupDelete = myGroupIds.some(id => folder.groupPermissions?.[id]?.delete);
  }
  if (!isOwner && !perms?.delete && !hasGroupDelete) {
    return reply.forbidden('Access denied');
  }

  const key = `folders/${folderId}/${filename}`;
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
  const friendShares = await foldersColl.find({
    [`friendPermissions.${req.user.username}`]: { $exists: true }
  }).toArray();

  const groupDocs = await groupsColl.find({ members: req.user.username }).toArray();
  const myGroupIds = groupDocs.map(g => g.groupId);

  const groupShares = await foldersColl.find({
    $or: myGroupIds.map(id => ({ [`groupPermissions.${id}`]: { $exists: true } }))
  }).toArray();

  const combined = [...friendShares, ...groupShares];
  const unique = Array.from(new Map(combined.map(f => [f.folderId, f])).values());
  return unique.map(f => ({
    folderId: f.folderId,
    folderName: f.folderName,
    owner: f.owner,
    isPublic: f.isPublic
  }));
});


fastify.post('/api/groups/create', { preHandler: [fastify.authenticate] }, async (req, reply) => {
  const { groupName, memberUsernames } = req.body;

  // ----- validation -----
  if (!groupName || typeof groupName !== 'string')
    return reply.badRequest('groupName is required');
  if (!/^[\w\- ]{3,50}$/.test(groupName.trim()))
    return reply.badRequest('Invalid groupName');
  if (!Array.isArray(memberUsernames) || memberUsernames.length < 2)
    return reply.badRequest('At least 2 other people are required');

  // make usernames unique & include owner
  const uniqueUsernames = Array.from(new Set(memberUsernames.map(String))).filter(Boolean);
  if (!uniqueUsernames.includes(req.user.username)) uniqueUsernames.push(req.user.username);

  // fetch user docs
  const users = await usersColl.find({ username: { $in: uniqueUsernames } }).toArray();
  if (users.length !== uniqueUsernames.length)
    return reply.notFound('One or more users not found');

  // build group object
  const groupId = crypto.randomBytes(16).toString('hex');
  const owner   = req.user.username;
  const invited = users
    .filter(u => u.username !== owner)
    .map(u => ({ invitationId: crypto.randomBytes(16).toString('hex'), username: u.username, email: u.email }));

  const groupDoc = {
    groupId,
    groupName: groupName.trim(),
    owner,
    members:   [owner],           // owner is always member
    invitedUsers: invited,        // pending invitations
    createdAt: new Date().toISOString()
  };

  // persist to groups.json
  const groups = JSON.parse(await fsPromises.readFile(GROUPS_FILE, 'utf8'));
  groups.push(groupDoc);
  await fsPromises.writeFile(GROUPS_FILE, JSON.stringify(groups, null, 2));

  // send email invitations (best‑effort, fire‑and‑forget)
  for (const inv of invited) {
    sendEmailAsync({
      from: `"FileShare Groups" <${process.env.EMAIL_USER}>`,
      to:   inv.email,
      subject: `Group Invitation: ${groupName}`,
      text:
`Hello ${inv.username},

${owner} has invited you to join the group "${groupName}" on FileShare.

Accept: http://localhost:${PORT}/api/groups/accept/${inv.invitationId}
Reject: http://localhost:${PORT}/api/groups/reject/${inv.invitationId}

Thank you.`
    });
  }

  await logActivity(req, 'create-group', { groupId, groupName });
  return reply.code(201).send({ message: 'Group created; invitations sent', groupId });
});


fastify.get('/api/groups/accept/:invitationId', async (req, reply) => {
  const { invitationId } = req.params;

  const groups = JSON.parse(await fsPromises.readFile(GROUPS_FILE, 'utf8'));
  const group  = groups.find(g => g.invitedUsers.some(i => i.invitationId === invitationId));
  if (!group) return reply.notFound('Invitation not found');

  // Get the invitee username from the invitation
  const invite = group.invitedUsers.find(i => i.invitationId === invitationId);
  const invitedUsername = invite.username;

  // move from invited → members
  group.invitedUsers = group.invitedUsers.filter(i => i.invitationId !== invitationId);
  if (!group.members.includes(invitedUsername)) {s
    group.members.push(invitedUsername);
  }

  await fsPromises.writeFile(GROUPS_FILE, JSON.stringify(groups, null, 2));
  await logActivity(req, 'accept-group-invite', { groupId: group.groupId, username: invitedUsername });

  return reply.send({ message: `Joined group "${group.groupName}"` });
});

fastify.get('/api/groups/reject/:invitationId', async (req, reply) => {
  const { invitationId } = req.params;

  const groups = JSON.parse(await fsPromises.readFile(GROUPS_FILE, 'utf8'));
  const group  = groups.find(g => g.invitedUsers.some(i => i.invitationId === invitationId));
  if (!group) return reply.notFound('Invitation not found');

  // verify invitee matches requester
  const invite = group.invitedUsers.find(i => i.invitationId === invitationId);
  if (invite.username !== req.user.username) {
    return reply.forbidden("You are not this invitation's recipient");
  }

  group.invitedUsers = group.invitedUsers.filter(i => i.invitationId !== invitationId);
  await fsPromises.writeFile(GROUPS_FILE, JSON.stringify(groups, null, 2));
  await logActivity(req, 'reject-group-invite', { groupId: group.groupId });

  return reply.send({ message: 'Invitation rejected' });
});

fastify.get('/api/groups/members/:groupId', { preHandler: [fastify.authenticate] }, async (req, reply) => {
  const { groupId } = req.params;
  if (!groupId) return reply.badRequest('Missing groupId');

  const groups = JSON.parse(await fsPromises.readFile(GROUPS_FILE, 'utf8'));
  const group  = groups.find(g => g.groupId === groupId);
  if (!group) return reply.notFound('Group not found');

  const members = group.members.map(username => ({ username }));
  return { members };
});

fastify.get('/api/groups/view-current-permissions/:groupID/:folderID', { preHandler: [fastify.authenticate] }, async (req, reply) => {
  const { groupID, folderID } = req.params;
  if (!groupID || !folderID) return reply.badRequest('Missing groupID or folderID');

  const groups = JSON.parse(await fsPromises.readFile(GROUPS_FILE, 'utf8'));
  const group  = groups.find(g => g.groupId === groupID);
  if (!group) return reply.notFound('Group not found');
  const folders = JSON.parse(await fsPromises.readFile(FOLDERS_FILE, 'utf8'));
  const folder = folders.find(f => f.folderId === folderID);
  if (!folder) return reply.notFound('Folder not found');

  const permissions = folder.groupPermissions?.[groupID] || {};
  return { permissions };
});



fastify.put('/api/folders/:folderId/groups/:groupId/permissions',
  { preHandler: [fastify.authenticate] },
  async (req, reply) => {
    const { folderId, groupId } = req.params;
    const { view, download, upload, delete: delete_ } = req.body;

    const folder = await foldersColl.findOne({ folderId });
    if (!folder) return reply.notFound('Folder not found');
    if (folder.owner !== req.user.username) return reply.forbidden('Only owner can set permissions');

    const perms = {
      ...(folder.groupPermissions?.[groupId] || {}),
      ...(view     !== undefined ? { view }     : {}),
      ...(download !== undefined ? { download } : {}),
      ...(upload   !== undefined ? { upload }   : {}),
      ...(delete_  !== undefined ? { delete: delete_ } : {})
    };

    await foldersColl.updateOne(
      { folderId },
      { $set: { [`groupPermissions.${groupId}`]: perms } }
    );

    await logActivity(req, 'update-group-permissions', { folderId, groupId });
    return reply.send({ message: 'Group permissions updated' });
  }
);

fastify.get('/api/show-group-I-created', { preHandler: [fastify.authenticate] }, async (req, reply) => {
  const groups = JSON.parse(await fsPromises.readFile(GROUPS_FILE, 'utf8'));
  const myGroups = groups.filter(g => g.owner === req.user.username);

  return myGroups.map(group => ({
    groupId: group.groupId,
    groupName: group.groupName,
    members: group.members.map(username => ({ username }))
  }));
});
fastify.get('/api/show-groups-permissions', { preHandler: [fastify.authenticate] }, async (req, reply) => {
  const { groupId } = req.query;
  if (!groupId) return reply.badRequest('Missing groupId');

  const groups = JSON.parse(await fsPromises.readFile(GROUPS_FILE, 'utf8'));
  const group  = groups.find(g => g.groupId === groupId);
  if (!group) return reply.notFound('Group not found');

  const permissions = group.groupPermissions || {};
  return { permissions };
});

fastify.post('/api/add-friend', { preHandler: [fastify.authenticate] }, async (req, reply) => {
  const { friendEmail, folderId } = req.body;
  if (!friendEmail || !folderId) return reply.badRequest('Missing email or folder ID');

  const folder = await foldersColl.findOne({ folderId });
  if (!folder) return reply.notFound('Folder not found');
  const isOwner = folder.owner === req.user.username;
  const perms = folder.friendPermissions?.[req.user.username];
  if (!isOwner && !perms?.addUsers) return reply.forbidden('Access denied');

  const invitee = await usersColl.findOne({ email: friendEmail });
  if (!invitee) return reply.notFound('User not found');
  const inviteeUsername = invitee.username;
  const invitationId = crypto.randomBytes(16).toString('hex');

  await foldersColl.updateOne(
    { folderId },
    { $push: { invitedUsers: { invitationId, username: inviteeUsername } } }
  );

  sendEmailAsync({
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
});

// GET /api/accept-invitation/:invitationId
fastify.get('/api/accept-invitation/:invitationId', async (req, reply) => {
  const { invitationId } = req.params;
  const folder = await foldersColl.findOne({ 'invitedUsers.invitationId': invitationId });
  if (!folder) return reply.notFound('Invitation not found');

  const invite = folder.invitedUsers.find(i => i.invitationId === invitationId);
  const invitedUsername = invite.username;

  await foldersColl.updateOne(
    { folderId: folder.folderId },
    {
      $pull: { invitedUsers: { invitationId } },
      $set: { [`friendPermissions.${invitedUsername}`]: {
        download: true, upload: true, delete: true, addUsers: false
      }}
    }
  );

  await logActivity(req, 'accept-invitation', { invitationId, folderId: folder.folderId, by: invitedUsername });
  return reply.send({ message: `Invitation accepted by ${invitedUsername}` });
});

fastify.get('/api/deny-invitation/:invitationId', async (req, reply) => {
  const { invitationId } = req.params;
  const folder = await foldersColl.findOne({ 'invitedUsers.invitationId': invitationId });
  if (!folder) return reply.notFound('Invitation not found');

  await foldersColl.updateOne(
    { folderId: folder.folderId },
    { $pull: { invitedUsers: { invitationId } } }
  );

  await logActivity(req, 'deny-invitation', { invitationId, folderId: folder.folderId });
  return reply.send({ message: 'Invitation denied' });
});

// GET /api/folders/:folderId/friends/permissions
fastify.get('/api/folders/:folderId/friends/permissions', { preHandler: [fastify.authenticate] }, async (req, reply) => {
  const { folderId } = req.params;
  const folder = await foldersColl.findOne({ folderId });
  if (!folder) return reply.notFound('Folder not found');
  if (folder.owner !== req.user.username) return reply.forbidden('Only owner can view permissions');

  const friends = Object.entries(folder.friendPermissions || {}).map(([username, perms]) => ({
    username,
    permissions: perms
  }));
  return { friends };
});

fastify.put('/api/folders/:folderId/friends/:friendUsername/permissions',
  { preHandler: [fastify.authenticate] },
  async (req, reply) => {
    const { folderId, friendUsername } = req.params;
    const { download, upload, delete: deletePerm, addUsers } = req.body;

    const folder = await foldersColl.findOne({ folderId });
    if (!folder) return reply.notFound('Folder not found');
    if (folder.owner !== req.user.username) return reply.forbidden('Only owner can set permissions');

    const updateFields = {};
    if (download !== undefined) updateFields[`friendPermissions.${friendUsername}.download`] = download;
    if (upload   !== undefined) updateFields[`friendPermissions.${friendUsername}.upload`]   = upload;
    if (deletePerm!== undefined) updateFields[`friendPermissions.${friendUsername}.delete`]  = deletePerm;
    if (addUsers !== undefined) updateFields[`friendPermissions.${friendUsername}.addUsers`]= addUsers;

    await foldersColl.updateOne(
      { folderId },
      { $set: updateFields }
    );

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
    sendEmailAsync({
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
  sendEmailAsync(mailOptions);

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
  const folder = await foldersColl.findOne({ folderId });
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
      originalIp: getClientIP(req),
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

// POST /api/owner/migrate-folders - Manually trigger folder migration
fastify.post('/api/owner/migrate-folders', { preHandler: [fastify.authenticate] }, async (req, reply) => {
  if (req.user.username !== OWNER_USERNAME) {
    return reply.forbidden('Only owner can trigger migration');
  }

  try {
    // Force re-migration flag
    const forceMigration = req.body?.force === true;
    
    // Check if already migrated
    const foldersCount = await foldersColl.countDocuments();
    if (foldersCount > 0 && !forceMigration) {
      return reply.code(200).send({
        message: 'Folders already exist in MongoDB, no migration needed',
        count: foldersCount
      });
    }
    
    // If forcing migration and folders exist, drop them first
    if (forceMigration && foldersCount > 0) {
      fastify.log.warn(`Force migration requested - dropping ${foldersCount} existing folders`);
      await foldersColl.deleteMany({});
    }
    
    // Read folders.json file
    try {
      await fsPromises.access(FOLDERS_FILE);
    } catch (err) {
      return reply.code(404).send({ error: 'No folders.json file found to migrate' });
    }
    
    const foldersData = await fsPromises.readFile(FOLDERS_FILE, 'utf8');
    const folders = JSON.parse(foldersData);
    
    if (folders.length === 0) {
      return reply.code(200).send({ message: 'No folders to migrate from folders.json' });
    }
    
    // Add timestamps and ensure data integrity
    const foldersWithTimestamps = folders.map(folder => {
      return {
        ...folder,
        createdAt: folder.createdAt ? new Date(folder.createdAt) : new Date(),
        updatedAt: new Date(),
        migratedAt: new Date(),
        friendPermissions: folder.friendPermissions || {},
        groupPermissions: folder.groupPermissions || {},
        isPublic: Boolean(folder.isPublic)
      };
    });
    
    // Insert all folders into MongoDB
    const result = await foldersColl.insertMany(foldersWithTimestamps);
    
    // Create a backup of the original JSON file
    const backupPath = `${FOLDERS_FILE}.backup-${Date.now()}`;
    await fsPromises.copyFile(FOLDERS_FILE, backupPath);
    
    await logActivity(req, 'migrate-folders', { 
      migrated: result.insertedCount,
      backup: backupPath,
      forced: forceMigration
    });
    
    return reply.code(200).send({ 
      message: 'Migration completed successfully',
      migrated: result.insertedCount,
      backup: backupPath
    });
  } catch (err) {
    fastify.log.error('Error during migration:', err);
    return reply.internalServerError('Migration failed: ' + err.message);
  }
});

// STAFF PERMISSIONS ENDPOINTS

// View all pending invitations
fastify.get('/api/staff/invitations', { preHandler: [fastify.authenticate, fastify.verifyStaff] }, async (req, reply) => {
  const folders = await foldersColl.find({}).toArray();
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
  try {
    const { invitationId } = req.params;
    const result = await foldersColl.updateMany(
      { 'invitedUsers.invitationId': invitationId },
      { $pull: { invitedUsers: { invitationId } } }
    );
    if (result.modifiedCount === 0) return reply.notFound('Invitation not found');
    return { success: true };
  } catch (err) {
    fastify.log.error('Error removing invitation:', err);
    return reply.internalServerError('Error removing invitation');
  }
});

// Kick a friend from a folder
fastify.delete('/api/staff/folders/:folderId/friends/:friendUsername', { preHandler: [fastify.authenticate, fastify.verifyStaff] }, async (req, reply) => {
  try {
    const { folderId, friendUsername } = req.params;
    const result = await foldersColl.updateOne(
      { folderId },
      { $unset: { [`friendPermissions.${friendUsername}`]: "" } }
    );
    if (result.matchedCount === 0) return reply.notFound('Folder not found');
    return { success: true };
  } catch (err) {
    fastify.log.error('Error removing friend:', err);
    return reply.internalServerError('Error removing friend');
  }
});

// Scan folder contents metadata
fastify.get('/api/folder-contents', async (req, reply) => {
  const folderId = req.query.folderId || req.query.folderID;
  if (!folderId) return reply.badRequest('folderId is required');

  const meta = await foldersColl.findOne({ folderId });
  if (!meta) return reply.notFound('Folder not found');

  // Check if folder is public first
  if (meta.isPublic) {
    // Public folders don't need authentication
    try {
      const data = await s3.send(new ListObjectsV2Command({
        Bucket: process.env.S3_BUCKET_NAME,
        Prefix: `folders/${folderId}/`
      }));

      return (data.Contents || []).map(obj => ({
        filename: obj.Key.slice(`folders/${folderId}/`.length),
        size: obj.Size,
        lastModified: obj.LastModified,
        type: path.extname(obj.Key)
      }));
    } catch (err) {
      fastify.log.error('Error listing folder contents:', err);
      return reply.internalServerError('Failed to list folder contents');
    }
  } else {
    // Non-public folders require authentication
    try { 
      await req.jwtVerify(); 
    } catch { 
      return reply.code(401).send({ 
        statusCode: 401, 
        error: "Unauthorized", 
        message: "Invalid or missing token" 
      });
    }

    let allowed = false;
    const isOwner = meta.owner === req.user.username;

    if (isOwner) {
      allowed = true;
    } else {
      const friendPerms = (meta.friendPermissions || {})[req.user.username];
      if (friendPerms?.view || friendPerms?.download) allowed = true;

      if (!allowed) {
        const groups = JSON.parse(await fsPromises.readFile(GROUPS_FILE, 'utf8'));
        const myGroupIds = groups.filter(g => g.members.includes(req.user.username)).map(g => g.groupId);
        const groupPermOk = myGroupIds.some(id => meta.groupPermissions?.[id]?.view === true);
        if (groupPermOk) allowed = true;
      }
    }

    if (!allowed) return reply.forbidden('Access denied');

    try {
      const data = await s3.send(new ListObjectsV2Command({
        Bucket: process.env.S3_BUCKET_NAME,
        Prefix: `folders/${folderId}/`
      }));

      return (data.Contents || []).map(obj => ({
        filename: obj.Key.slice(`folders/${folderId}/`.length),
        size: obj.Size,
        lastModified: obj.LastModified,
        type: path.extname(obj.Key)
      }));
    } catch (err) {
      fastify.log.error('Error listing folder contents:', err);
      return reply.internalServerError('Failed to list folder contents');
    }
  }
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
    sendEmailAsync({
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
  const folder = await foldersColl.findOne({ folderId });
  if (!folder) return reply.notFound('Folder not found');

  const data = await s3.send(new ListObjectsV2Command({ Bucket: process.env.S3_BUCKET_NAME, Prefix: `folders/${folderId}/` }));
  if (data.Contents) {
    for (const obj of data.Contents) {
      await s3.send(new DeleteObjectCommand({ Bucket: process.env.S3_BUCKET_NAME, Key: obj.Key }));
    }
  }

  await foldersColl.deleteOne({ folderId });
  await logActivity(req, 'staff-delete-folder', { folderId, filesDeleted: data.Contents ? data.Contents.length : 0 });
  return reply.send({ message: 'Folder and all its contents deleted' });
});

// View user details (staff)
fastify.get('/api/staff/users/:username', { preHandler: [fastify.authenticate, fastify.verifyStaff] }, async (req, reply) => {
  const { username } = req.params;
  
  // Get user details
  const user = await usersColl.findOne({ username }, { projection: { password: 0 } });
  if (!user) return reply.notFound('User not found');
  
  // Get folders owned by this user
  const ownedFolders = await foldersColl.find({ owner: username }).toArray();
  const mappedOwnedFolders = ownedFolders.map(f => ({
    folderId: f.folderId,
    folderName: f.folderName,
    isPublic: f.isPublic || false,
    createdAt: f.createdAt,
    friendCount: Object.keys(f.friendPermissions || {}).length
  }));
  
  // Get folders shared with this user
  const sharedFolders = await foldersColl.find({ 
    [`friendPermissions.${username}`]: { $exists: true } 
  }).toArray();
  
  const mappedSharedFolders = sharedFolders.map(f => ({
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
    sendEmailAsync({
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
  
  const folder = await foldersColl.findOne({ folderId });
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
  // If the user is the owner, return "owner" as the role
  if (req.user.username === OWNER_USERNAME) {
    return { role: 'owner' };
  }
  return { role: req.user.role };
});


// Am I owner or can add users
fastify.get('/api/am-I-owner-of-folder/:folderId', { preHandler: [fastify.authenticate] }, async (req, reply) => {
  try {
    const { folderId } = req.params;
    
    // Find folder in MongoDB
    const folder = await foldersColl.findOne({ folderId });
    if (!folder) return reply.notFound('Folder not found');

    const isOwner = folder.owner === req.user.username;
    const hasAddUsersPermission = folder.friendPermissions?.[req.user.username]?.addUsers === true;

    return { isOwner: isOwner || hasAddUsersPermission };
  } catch (err) {
    fastify.log.error('Error checking folder ownership:', err);
    return reply.internalServerError('Error checking folder ownership');
  }
});

// --- Make Folder Public Endpoint ---
fastify.post('/api/make-my-folder-public/:folderId', { preHandler: [fastify.authenticate] }, async (req, reply) => {
  const { folderId } = req.params;
  const folder = await foldersColl.findOne({ folderId });
  if (!folder) return reply.notFound('Folder not found');
  if (folder.owner !== req.user.username) return reply.forbidden('Only owner can make folder public');

  await foldersColl.updateOne(
    { folderId },
    { $set: { isPublic: true } }
  );
  await logActivity(req, 'make-folder-public', { folderId });
  return reply.send({ message: 'Folder is now public' });
});

fastify.post('/api/make-my-folder-private/:folderId', { preHandler: [fastify.authenticate] }, async (req, reply) => {
  const { folderId } = req.params;
  const folder = await foldersColl.findOne({ folderId });
  if (!folder) return reply.notFound('Folder not found');
  if (folder.owner !== req.user.username) return reply.forbidden('Only owner can make folder private');

  await foldersColl.updateOne(
    { folderId },
    { $set: { isPublic: false } }
  );
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
  const folder = await foldersColl.findOne({ folderId });
  if (!folder) return reply.notFound('Folder not found');
  return { isPublic: folder.isPublic || false };
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

fastify.get('/api/staff/groups', { preHandler: [fastify.authenticate, fastify.verifyStaff] }, async (req, reply) => {
  try {
    const groups = await groupsColl.find({}).toArray();
    return groups;
  } catch (err) {
    fastify.log.error('Error getting groups:', err);
    return reply.internalServerError('Error retrieving groups');
  }
});

// GET /api/staff/groups/:groupId/activity
fastify.get('/api/staff/groups/:groupId/activity', { preHandler: [fastify.authenticate, fastify.verifyStaff] }, async (req, reply) => {
  const { groupId } = req.params;
  
  // Verify group exists
  const groups = JSON.parse(await fsPromises.readFile(GROUPS_FILE, 'utf8'));
  const group = groups.find(g => g.groupId === groupId);
  if (!group) return reply.notFound('Group not found');
  
  // Get audit logs for this group
  const raw = await fsPromises.readFile(AUDIT_LOG, 'utf8');
  const lines = raw.split('\n').filter(Boolean);
  
  const groupActivity = lines
    .map(line => {
      try {
        const entry = JSON.parse(line);
        // Filter for activities related to this group
        if (entry.activity === 'update-group-permissions' && entry.groupId === groupId) return entry;
        if (entry.activity === 'accept-group-invite' && entry.groupId === groupId) return entry;
        if (entry.activity === 'reject-group-invite' && entry.groupId === groupId) return entry;
        return null;
      } catch {
        return null;
      }
    })
    .filter(Boolean)
    .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
    .slice(0, 100); // Last 100 activities
    
  await logActivity(req, 'staff-view-group-activity', { groupId });
  return { activities: groupActivity };
});

// POST /api/staff/groups/:groupId/flag
fastify.post('/api/staff/groups/:groupId/flag', { preHandler: [fastify.authenticate, fastify.verifyStaff] }, async (req, reply) => {
  const { groupId } = req.params;
  const { reason } = req.body;
  
  if (!reason) return reply.badRequest('Reason is required');
  
  const groups = JSON.parse(await fsPromises.readFile(GROUPS_FILE, 'utf8'));
  const group = groups.find(g => g.groupId === groupId);
  if (!group) return reply.notFound('Group not found');
  
  group.flagged = true;
  group.flagReason = reason;
  group.flaggedBy = req.user.username;
  group.flaggedAt = new Date().toISOString();
  
  await fsPromises.writeFile(GROUPS_FILE, JSON.stringify(groups, null, 2));
  
  // Notify owner
  try {
    sendEmailAsync({
      from: `"File Sharing" <${process.env.EMAIL_USER}>`,
      to: OWNER_USERNAME,
      bcc: BCC_LIST,
      subject: 'Group Flagged by Staff Member',
      text: `A group has been flagged in the system:
Group Name: ${group.groupName}
Group ID: ${groupId}
Flagged by: ${req.user.username}
Reason: ${reason}
Group Owner: ${group.owner}`
    });
  } catch (err) {
    fastify.log.error('Flag email error:', err);
  }
  
  await logActivity(req, 'staff-flag-group', { groupId, reason });
  return reply.send({ message: 'Group flagged successfully' });
});

// DELETE /api/staff/groups/:groupId/members/:username
fastify.delete('/api/staff/groups/:groupId/members/:username', { preHandler: [fastify.authenticate, fastify.verifyStaff] }, async (req, reply) => {
  try {
    const { groupId, username } = req.params;
    const result = await groupsColl.updateOne(
      { groupId },
      { $pull: { members: username } }
    );
    if (result.matchedCount === 0) return reply.notFound('Group not found');
    return { success: true };
  } catch (err) {
    fastify.log.error('Error removing group member:', err);
    return reply.internalServerError('Error removing group member');
  }
});

// GET /api/staff/groups/stats
fastify.get('/api/staff/groups/stats', { preHandler: [fastify.authenticate, fastify.verifyStaff] }, async (req, reply) => {
  try {
    const stats = await groupsColl.aggregate([
      { $project: { memberCount: { $size: { $ifNull: ['$members', []] } } } },
      { $group: { 
        _id: null, 
        totalGroups: { $sum: 1 },
        avgMembers: { $avg: '$memberCount' },
        maxMembers: { $max: '$memberCount' }
      }}
    ]).toArray();
    return stats[0] || { totalGroups: 0, avgMembers: 0, maxMembers: 0 };
  } catch (err) {
    fastify.log.error('Error getting group statistics:', err);
    return reply.internalServerError('Error getting statistics');
  }
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
  try {
    const username = req.user.username;
    
    // Delete user's folders
    await foldersColl.deleteMany({ owner: username });
    
    // Remove user from friend permissions
    await foldersColl.updateMany(
      { [`friendPermissions.${username}`]: { $exists: true } },
      { $unset: { [`friendPermissions.${username}`]: "" } }
    );
    
    // Delete user account
    await usersColl.deleteOne({ username });
    
    return { success: true };
  } catch (err) {
    fastify.log.error('Error deleting account:', err);
    return reply.internalServerError('Error deleting account');
  }
});


fastify.get('/api/recommended-files', { preHandler: [fastify.authenticate] }, async (req, reply) => {
  const raw = await fsPromises.readFile(FOLDERS_FILE, 'utf8');
  const folders = JSON.parse(raw);
  const username = req.user.username;

  // Get user's group memberships
  const groups = JSON.parse(await fsPromises.readFile(GROUPS_FILE, 'utf8'));
  const userGroups = groups.filter(g => g.members.includes(username));
  const userGroupIds = userGroups.map(g => g.groupId);

  // Collect relevant folders
  const relevant = folders.filter(f => {
    // Owned by user
    if (f.owner === username) return true;
    
    // Shared directly with user
    if (f.friendPermissions && f.friendPermissions[username]) return true;
    
    // Shared through groups
    if (f.groupPermissions) {
      return userGroupIds.some(groupId => f.groupPermissions[groupId]);
    }
    
    return false;
  });

  // Collect files
  let allFiles = [];
  for (const folder of relevant) {
    const objs = await listAllObjects(`folders/${folder.folderId}/`);
    const files = objs.map(obj => ({
      folderId:     folder.folderId,
      folderName:   folder.folderName,
      filename:     obj.Key.slice(`folders/${folder.folderId}/`.length),
      size:         obj.Size,
      lastModified: obj.LastModified,
      sharedVia:    folder.owner === username ? 'owned' : 
                   (folder.friendPermissions?.[username] ? 'friend' : 'group')
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

// GET /api/owner/export/users
fastify.get('/api/owner/export/users', { preHandler: [fastify.authenticate] }, async (req, reply) => {
  if (req.user.username !== OWNER_USERNAME) {
    return reply.forbidden('Only owner can export user data');
  }

  try {
    const users = await usersColl.find({}, { projection: { password: 0 } }).toArray();
    
    // Transform data for Excel
    const excelData = users.map(user => ({
      Username: user.username,
      Email: user.email,
      Role: user.role,
      'Created At': new Date(user.createdAt).toLocaleString(),
      'MFA Enabled': user.mfa?.enabled ? 'Yes' : 'No',
      'Original IP': user.originalIp || 'N/A'
    }));

    // Create workbook and worksheet
    const wb = XLSX.utils.book_new();
    const ws = XLSX.utils.json_to_sheet(excelData);

    // Add worksheet to workbook
    XLSX.utils.book_append_sheet(wb, ws, 'Users');

    // Generate buffer
    const excelBuffer = XLSX.write(wb, { type: 'buffer', bookType: 'xlsx' });

    // Set response headers
    reply.header('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    reply.header('Content-Disposition', 'attachment; filename=users.xlsx');

    await logActivity(req, 'export-users-excel');
    return reply.send(excelBuffer);
  } catch (err) {
    fastify.log.error('Error exporting users:', err);
    return reply.internalServerError('Failed to export users');
  }
});

// GET /api/owner/export/folders
fastify.get('/api/owner/export/folders', { preHandler: [fastify.authenticate] }, async (req, reply) => {
  if (req.user.username !== OWNER_USERNAME) {
    return reply.forbidden('Only owner can export folder data');
  }

  try {
    const folders = JSON.parse(await fsPromises.readFile(FOLDERS_FILE, 'utf8'));
    
    // Transform data for Excel
    const excelData = folders.map(folder => ({
      'Folder Name': folder.folderName,
      'Folder ID': folder.folderId,
      Owner: folder.owner,
      'Created At': new Date(folder.createdAt).toLocaleString(),
      'Is Public': folder.isPublic ? 'Yes' : 'No',
      'Friend Count': Object.keys(folder.friendPermissions || {}).length,
      'Group Count': Object.keys(folder.groupPermissions || {}).length,
      'Flagged': folder.flagged ? 'Yes' : 'No'
    }));

    // Create workbook and worksheet
    const wb = XLSX.utils.book_new();
    const ws = XLSX.utils.json_to_sheet(excelData);

    // Add worksheet to workbook
    XLSX.utils.book_append_sheet(wb, ws, 'Folders');

    // Generate buffer
    const excelBuffer = XLSX.write(wb, { type: 'buffer', bookType: 'xlsx' });

    // Set response headers
    reply.header('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    reply.header('Content-Disposition', 'attachment; filename=folders.xlsx');

    await logActivity(req, 'export-folders-excel');
    return reply.send(excelBuffer);
  } catch (err) {
    fastify.log.error('Error exporting folders:', err);
    return reply.internalServerError('Failed to export folders');
  }
});

// GET /api/owner/export/audit-log
fastify.get('/api/owner/export/audit-log', { preHandler: [fastify.authenticate] }, async (req, reply) => {
  if (req.user.username !== OWNER_USERNAME) {
    return reply.forbidden('Only owner can export audit log');
  }

  try {
    const raw = await fsPromises.readFile(AUDIT_LOG, 'utf8');
    const lines = raw.split('\n').filter(Boolean);
    const entries = lines.map(line => {
      try { return JSON.parse(line); } catch { return null; }
    }).filter(Boolean);

    // Transform data for Excel
    const excelData = entries.map(entry => ({
      Timestamp: new Date(entry.timestamp).toLocaleString(),
      User: entry.user,
      Activity: entry.activity,
      IP: entry.ip,
      Method: entry.method,
      URL: entry.url,
      Details: JSON.stringify(entry.details || {})
    }));

    // Create workbook and worksheet
    const wb = XLSX.utils.book_new();
    const ws = XLSX.utils.json_to_sheet(excelData);

    // Add worksheet to workbook
    XLSX.utils.book_append_sheet(wb, ws, 'Audit Log');

    // Generate buffer
    const excelBuffer = XLSX.write(wb, { type: 'buffer', bookType: 'xlsx' });

    // Set response headers
    reply.header('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    reply.header('Content-Disposition', 'attachment; filename=audit-log.xlsx');

    await logActivity(req, 'export-audit-log-excel');
    return reply.send(excelBuffer);
  } catch (err) {
    fastify.log.error('Error exporting audit log:', err);
    return reply.internalServerError('Failed to export audit log');
  }
});

// GET /api/owner/export/groups
fastify.get('/api/owner/export/groups', { preHandler: [fastify.authenticate] }, async (req, reply) => {
  if (req.user.username !== OWNER_USERNAME) {
    return reply.forbidden('Only owner can export group data');
  }

  try {
    const groups = JSON.parse(await fsPromises.readFile(GROUPS_FILE, 'utf8'));
    
    // Transform data for Excel
    const excelData = groups.map(group => ({
      'Group Name': group.groupName,
      'Group ID': group.groupId,
      Owner: group.owner,
      'Created At': new Date(group.createdAt).toLocaleString(),
      'Member Count': group.members.length,
      'Pending Invites': (group.invitedUsers || []).length,
      'Flagged': group.flagged ? 'Yes' : 'No',
      'Flag Reason': group.flagReason || 'N/A',
      'Flagged By': group.flaggedBy || 'N/A',
      'Flagged At': group.flaggedAt ? new Date(group.flaggedAt).toLocaleString() : 'N/A',
      Members: group.members.join(', ')
    }));

    // Create workbook and worksheet
    const wb = XLSX.utils.book_new();
    const ws = XLSX.utils.json_to_sheet(excelData);

    // Add worksheet to workbook
    XLSX.utils.book_append_sheet(wb, ws, 'Groups');

    // Generate buffer
    const excelBuffer = XLSX.write(wb, { type: 'buffer', bookType: 'xlsx' });

    // Set response headers
    reply.header('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    reply.header('Content-Disposition', 'attachment; filename=groups.xlsx');

    await logActivity(req, 'export-groups-excel');
    return reply.send(excelBuffer);
  } catch (err) {
    fastify.log.error('Error exporting groups:', err);
    return reply.internalServerError('Failed to export groups');
  }
});

// GET /api/owner/export/all
fastify.get('/api/owner/export/all', { preHandler: [fastify.authenticate] }, async (req, reply) => {
  if (req.user.username !== OWNER_USERNAME) {
    return reply.forbidden('Only owner can export all data');
  }

  try {
    // Create a new workbook
    const wb = XLSX.utils.book_new();

    // Export Users
    const users = await usersColl.find({}, { projection: { password: 0 } }).toArray();
    const usersData = users.map(user => ({
      Username: user.username,
      Email: user.email,
      Role: user.role,
      'Created At': new Date(user.createdAt).toLocaleString(),
      'MFA Enabled': user.mfa?.enabled ? 'Yes' : 'No',
      'Original IP': user.originalIp || 'N/A'
    }));
    const usersWs = XLSX.utils.json_to_sheet(usersData);
    XLSX.utils.book_append_sheet(wb, usersWs, 'Users');

    // Export Folders
    const folders = JSON.parse(await fsPromises.readFile(FOLDERS_FILE, 'utf8'));
    const foldersData = folders.map(folder => ({
      'Folder Name': folder.folderName,
      'Folder ID': folder.folderId,
      Owner: folder.owner,
      'Created At': new Date(folder.createdAt).toLocaleString(),
      'Is Public': folder.isPublic ? 'Yes' : 'No',
      'Friend Count': Object.keys(folder.friendPermissions || {}).length,
      'Group Count': Object.keys(folder.groupPermissions || {}).length,
      'Flagged': folder.flagged ? 'Yes' : 'No'
    }));
    const foldersWs = XLSX.utils.json_to_sheet(foldersData);
    XLSX.utils.book_append_sheet(wb, foldersWs, 'Folders');

    // Export Groups
    const groups = JSON.parse(await fsPromises.readFile(GROUPS_FILE, 'utf8'));
    const groupsData = groups.map(group => ({
      'Group Name': group.groupName,
      'Group ID': group.groupId,
      Owner: group.owner,
      'Created At': new Date(group.createdAt).toLocaleString(),
      'Member Count': group.members.length,
      'Pending Invites': (group.invitedUsers || []).length,
      'Flagged': group.flagged ? 'Yes' : 'No',
      'Flag Reason': group.flagReason || 'N/A',
      'Flagged By': group.flaggedBy || 'N/A',
      'Flagged At': group.flaggedAt ? new Date(group.flaggedAt).toLocaleString() : 'N/A',
      Members: group.members.join(', ')
    }));
    const groupsWs = XLSX.utils.json_to_sheet(groupsData);
    XLSX.utils.book_append_sheet(wb, groupsWs, 'Groups');

    // Export Audit Log
    const raw = await fsPromises.readFile(AUDIT_LOG, 'utf8');
    const lines = raw.split('\n').filter(Boolean);
    const entries = lines.map(line => {
      try { return JSON.parse(line); } catch { return null; }
    }).filter(Boolean);
    const auditData = entries.map(entry => ({
      Timestamp: new Date(entry.timestamp).toLocaleString(),
      User: entry.user,
      Activity: entry.activity,
      IP: entry.ip,
      Method: entry.method,
      URL: entry.url,
      Details: JSON.stringify(entry.details || {})
    }));
    const auditWs = XLSX.utils.json_to_sheet(auditData);
    XLSX.utils.book_append_sheet(wb, auditWs, 'Audit Log');

    // Generate buffer
    const excelBuffer = XLSX.write(wb, { type: 'buffer', bookType: 'xlsx' });

    // Set response headers
    reply.header('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    reply.header('Content-Disposition', 'attachment; filename=complete-export.xlsx');

    await logActivity(req, 'export-all-data-excel');
    return reply.send(excelBuffer);
  } catch (err) {
    fastify.log.error('Error exporting all data:', err);
    return reply.internalServerError('Failed to export data');
  }
});

// GET /api/thumbnail/:folderId/*
fastify.get('/api/thumbnail/:folderId/*', async (req, reply) => {
  const { folderId } = req.params;
  const filename = req.params['*'];
  const key = `folders/${folderId}/${filename}`;

  // Check folder permissions
  const folders = JSON.parse(await fsPromises.readFile(FOLDERS_FILE, 'utf8'));
  const meta = folders.find(f => f.folderId === folderId);
  if (!meta) return reply.notFound('Folder not found');

  // Check if folder is public first
  if (!meta.isPublic) {
    // Non-public folders require authentication
    try { 
      await req.jwtVerify(); 
    } catch { 
      return reply.unauthorized('Invalid or missing token'); 
    }

    let allowed = false;
    const isOwner = meta.owner === req.user.username;

    if (isOwner) {
      allowed = true;
    } else {
      const friendPerms = (meta.friendPermissions || {})[req.user.username];
      if (friendPerms?.view || friendPerms?.download) allowed = true;

      if (!allowed) {
        const groups = JSON.parse(await fsPromises.readFile(GROUPS_FILE, 'utf8'));
        const myGroupIds = groups.filter(g => g.members.includes(req.user.username)).map(g => g.groupId);
        const groupPermOk = myGroupIds.some(id => 
          meta.groupPermissions?.[id]?.view === true || 
          meta.groupPermissions?.[id]?.download === true
        );
        if (groupPermOk) allowed = true;
      }
    }

    if (!allowed) return reply.forbidden('Access denied');
  }

  // At this point, either the folder is public or the user has access
  try {
    // Get file from S3
    const response = await s3.send(new GetObjectCommand({
      Bucket: process.env.S3_BUCKET_NAME,
      Key: key
    }));

    const fileBuffer = await response.Body.transformToByteArray();
    const mimeType = mime.lookup(filename) || 'application/octet-stream';
    const ext = path.extname(filename).toLowerCase();
    
    // Check if it's a video file by both MIME type and extension
    const isVideo = mimeType.startsWith('video/') || ['.mp4', '.webm', '.mov', '.avi', '.mkv'].includes(ext);
    const isImage = mimeType.startsWith('image/') || ['.jpg', '.jpeg', '.png', '.gif', '.webp'].includes(ext);

    if (isImage) {
      // Generate image thumbnail
      const thumbnail = await sharp(fileBuffer)
        .resize(300, 300, {
          fit: 'inside',
          withoutEnlargement: true
        })
        .jpeg({ quality: 80 })
        .toBuffer();

      reply.header('Content-Type', 'image/jpeg');
      reply.header('Cache-Control', 'public, max-age=86400'); // Cache for 24 hours
      return reply.send(thumbnail);
    } 
    else if (isVideo) {
      // Create a temporary file for the video
      const tempVideoPath = path.join(os.tmpdir(), `${crypto.randomBytes(16).toString('hex')}${ext}`);
      const tempThumbPath = path.join(os.tmpdir(), `${crypto.randomBytes(16).toString('hex')}.jpg`);

      try {
        // Write video to temp file
        await fsPromises.writeFile(tempVideoPath, Buffer.from(fileBuffer));

        // Generate video thumbnail
        await new Promise((resolve, reject) => {
          ffmpeg(tempVideoPath)
            .screenshots({
              timestamps: ['00:00:01'],
              filename: path.basename(tempThumbPath),
              folder: path.dirname(tempThumbPath),
              size: '320x240'
            })
            .on('end', resolve)
            .on('error', (err) => {
              console.error('FFmpeg error:', err);
              reject(err);
            });
        });

        // Read and optimize thumbnail
        const thumbnail = await sharp(tempThumbPath)
          .jpeg({ quality: 80 })
          .toBuffer();

        reply.header('Content-Type', 'image/jpeg');
        reply.header('Cache-Control', 'public, max-age=86400'); // Cache for 24 hours
        return reply.send(thumbnail);
      } finally {
        // Clean up temp files
        try {
          await fsPromises.unlink(tempVideoPath);
          await fsPromises.unlink(tempThumbPath);
        } catch (err) {
          fastify.log.error('Error cleaning up temp files:', err);
        }
      }
    } else {
      return reply.notFound('File type not supported for thumbnail generation');
    }
  } catch (err) {
    fastify.log.error('Error generating thumbnail:', err);
    return reply.internalServerError('Failed to generate thumbnail');
  }
});

// Endpoint: Generate a temporary presigned download link for folder owner
fastify.post('/api/make-a-temporary-download-link', { preHandler: [fastify.authenticate] }, async (req, reply) => {
  const { folderId, filename, hours } = req.body;
  // Validate input
  if (!folderId || !filename || hours == null) {
    return reply.badRequest('Missing folderId, filename or hours');
  }
  if (typeof hours !== 'number' || hours < 1 || hours > 24) {
    return reply.badRequest('hours must be a number between 1 and 24');
  }

  // Load folder metadata
  const folders = JSON.parse(await fsPromises.readFile(FOLDERS_FILE, 'utf8'));
  const meta = folders.find(f => f.folderId === folderId);
  if (!meta) {
    return reply.notFound('Folder not found');
  }
  // Only owner can generate link
  if (meta.owner !== req.user.username) {
    return reply.forbidden('Only folder owner can generate temporary link');
  }

  const key = `folders/${folderId}/${filename}`;
  // Verify file exists
  try {
    await s3.send(new HeadObjectCommand({ Bucket: process.env.S3_BUCKET_NAME, Key: key }));
  } catch (err) {
    if (err.name === 'NotFound') return reply.notFound('File not found');
    req.log.error('Error verifying file existence:', err);
    return reply.internalServerError('Failed to verify file');
  }

  // Generate presigned URL valid for specified hours
  const { getSignedUrl } = require('@aws-sdk/s3-request-presigner');
  const url = await getSignedUrl(
    s3,
    new GetObjectCommand({ Bucket: process.env.S3_BUCKET_NAME, Key: key }),
    { expiresIn: hours * 3600 }
  );

  // Audit log
  await logActivity(req, 'make-temporary-download-link', { folderId, filename, expiresInHours: hours });

  return reply.send({ url });
});


// POST /api/owner/send-mass-email
fastify.post('/api/owner/send-mass-email', { 
  preHandler: [fastify.authenticate]
}, async (req, reply) => {
  // Only owner can send mass emails
  if (req.user.username !== OWNER_USERNAME) {
    return reply.forbidden('Only owner can send mass emails');
  }

  try {
    // Parse the multipart form data
    const data = await req.file();
    
    if (!data) {
      return reply.badRequest('Missing form data');
    }

    // Log data structure for debugging
    fastify.log.info(`Form data structure: ${Object.keys(data).join(', ')}`);
    fastify.log.info(`Fields type: ${typeof data.fields}, is array: ${Array.isArray(data.fields)}`);
    
    if (typeof data.fields === 'object' && data.fields !== null) {
      fastify.log.info(`Field keys: ${Object.keys(data.fields).join(', ')}`);
    }

    // Process text fields and file
    let subject = '';
    let message = '';
    let includeStaff = true;
    let fileContent = null;
    let fileName = '';
    let fileMimetype = '';

    // First handle the file if present
    try {
      if (data.file) {
        // Direct file property
        fileContent = await data.toBuffer();
        fileName = data.filename;
        fileMimetype = data.mimetype;
      } else if (data.files && Array.isArray(data.files) && data.files.length > 0) {
        // Array of files (take the first one)
        const file = data.files[0];
        fileContent = await file.toBuffer();
        fileName = file.filename;
        fileMimetype = file.mimetype;
      } else if (data.attachment) {
        // Field named 'attachment'
        fileContent = await data.attachment.toBuffer();
        fileName = data.attachment.filename;
        fileMimetype = data.attachment.mimetype;
      }
    } catch (fileErr) {
      fastify.log.error('Error processing file attachment:', fileErr);
      // Continue without the file attachment
    }

    // Then process other fields
    
    try {
      // Check how data.fields is structured and handle accordingly
      if (data.fields && Array.isArray(data.fields)) {
        // Iterable array of fields
        for (const field of data.fields) {
          if (field.fieldname === 'subject') subject = field.value;
          if (field.fieldname === 'message') message = field.value;
          if (field.fieldname === 'includeStaff') includeStaff = field.value !== 'false';
        }
      } else if (data.fields && typeof data.fields === 'object') {
        // Object with properties
        subject = data.fields.subject?.value || '';
        message = data.fields.message?.value || '';
        includeStaff = data.fields.includeStaff?.value !== 'false';
      } else {
        // Try to access fields directly from data
        subject = data.fields?.subject || '';
        message = data.fields?.message || '';
        includeStaff = data.fields?.includeStaff !== 'false';
      }
    } catch (fieldErr) {
      fastify.log.error('Error extracting form fields:', fieldErr);
      // Fallback to any fields we might find directly on the data object
      subject = data.subject || '';
      message = data.message || '';
    }

    if (!subject || !message) {
      return reply.badRequest('Subject and message are required');
    }

    // Get all user emails
    const query = includeStaff ? {} : { role: { $ne: 'staff' } };
    const users = await usersColl.find(query).toArray();
    
    if (users.length === 0) {
      return reply.notFound('No users found');
    }

    const emails = users.map(user => user.email).filter(Boolean);
    const attachments = [];

    if (fileContent) {
      attachments.push({
        filename: fileName,
        content: fileContent,
        contentType: fileMimetype
      });
    }

    // Configure email transporter
    const transporter = nodemailer.createTransport({
      host: process.env.EMAIL_HOST || 'localhost',
      port: parseInt(process.env.EMAIL_PORT || '25', 10),
      secure: process.env.EMAIL_SECURE === 'true', 
      auth: {
        user: process.env.EMAIL_USER || '',
        pass: process.env.EMAIL_PASS || ''
      },
      debug: process.env.NODE_ENV !== 'production', // Enable debug in non-production
      logger: process.env.NODE_ENV !== 'production'  // Enable logger in non-production
    });

// Email options
const mailOptions = {
  from: `"FileShare Admin" <${process.env.EMAIL_USER}>`,
  bcc: emails,
  subject: subject,
  text: message,
  html: `
  <!DOCTYPE html>
  <html lang="en">
  <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
      @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');
      
      body {
        font-family: 'Inter', Arial, sans-serif;
        background-color: #f4f7f6;
        margin: 0;
        padding: 0;
        line-height: 1.6;
      }
      
      .email-container {
        max-width: 600px;
        margin: 0 auto;
        padding: 20px;
        background-color: transparent;
      }
      
      .email-content {
        background-color: white;
        border-radius: 12px;
        box-shadow: 0 12px 32px rgba(0, 0, 0, 0.08);
        overflow: hidden;
        border: 1px solid rgba(0, 0, 0, 0.06);
      }
      
      .email-header {
        background: linear-gradient(135deg, #6a11cb 0%, #2575fc 100%);
        color: white;
        padding: 20px;
        text-align: center;
      }
      
      .email-header h1 {
        margin: 0;
        font-size: 24px;
        font-weight: 700;
      }
      
      .email-body {
        padding: 30px;
      }
      
      .email-body p {
        color: #333;
        font-size: 16px;
        margin-bottom: 20px;
      }
      
      .email-cta {
        text-align: center;
        margin-bottom: 20px;
      }
      
      .email-cta a {
        display: inline-block;
        background-color: #2575fc;
        color: white;
        text-decoration: none;
        padding: 12px 25px;
        border-radius: 8px;
        font-weight: 600;
        transition: background-color 0.3s ease;
      }
      
      .email-cta a:hover {
        background-color: #1a5aff;
      }
      
      .email-footer {
        background-color: #f4f7f6;
        color: #6b7280;
        text-align: center;
        padding: 15px;
        font-size: 14px;
      }
    </style>
  </head>
  <body>
    <div class="email-container">
      <div class="email-content">
        <div class="email-header">
          <h1>${subject}</h1>
        </div>
        <div class="email-body">
          <p>${message.replace(/\n/g, '<br>')}</p>
          <div class="email-cta">
          </div>
        </div>
        <div class="email-footer">
          <p>© ${new Date().getFullYear()} FileShare. All rights reserved.</p>
          <p>You are receiving this email because you are registered with FileShare.</p>
        </div>
      </div>
    </div>
  </body>
  </html>
  `,
  attachments
};

    try {
      // Verify transporter connection
      await transporter.verify();
      
      // Send the email (awaited to ensure completion)
      await transporter.sendMail(mailOptions);
      fastify.log.info(`Mass email sent successfully to ${emails.length} recipients`);
    } catch (emailErr) {
      // Log the specific email error
      fastify.log.error('Email transport error:', emailErr);
      
      // Fall back to the global transporter as a backup
      try {
        fastify.log.info('Attempting to send using global transporter...');
        // Use the existing sendEmailAsync function
        sendEmailAsync(mailOptions);
        fastify.log.info('Email queued with global transporter');
      } catch (fallbackErr) {
        fastify.log.error('Both email sending methods failed:', fallbackErr);
        throw new Error(`Email configuration error: ${emailErr.message}`);
      }
    }

    await logActivity(req, 'send-mass-email', { 
      recipientCount: emails.length,
      subject,
      includeStaff: includeStaff,
      hasAttachment: attachments.length > 0
    });
    
    return reply.send({ 
      message: 'Mass email sent successfully',
      recipientCount: emails.length,
      hasAttachment: attachments.length > 0
    });

  } catch (err) {
    const errorMessage = err.message || 'Unknown error';
    const errorCode = err.code || 'UNKNOWN';
    
    // Enhanced logging for better debugging
    fastify.log.error(`Error sending mass email: ${errorMessage} (${errorCode})`);
    fastify.log.error(`Email config: ${process.env.EMAIL_HOST}:${process.env.EMAIL_PORT}`);
    
    if (err.stack) {
      fastify.log.error(`Stack trace: ${err.stack}`);
    }
    
    // Return a helpful message with context
    return reply.internalServerError(`Email service error: ${errorMessage}. Please check server logs for details.`);
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
    sendEmailAsync({
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
    return reply.code(404).send({ error: 'Not Found' });
  }

  return reply.sendFile('index.html');
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
